'use strict';
// Minimal emulation of LuCI's client-side module system, enough to load the
// real files under htdocs/luci-static/resources/ into a jsdom document.
//
// What is emulated (mirroring modules/luci-base/htdocs/luci-static/resources/luci.js):
//   - the `'require name [as alias]'` string-statement scanner
//   - L.require(): dependency resolution, `(function(window, document, L, ...deps) { src })`
//     factory, the Class.isSubclass() check and the `new _class()` instantiation
//   - baseclass (LuCI.Class): extend / singleton / instantiate / isSubclass / super
//   - dom: create / append / content / attr / elem / parse, plus the E() alias
//   - view: a class with a no-op __init__ so tests drive load()/render() themselves
//   - poll: records the queue and lets a test fire an interval by hand
//   - ui: showModal / hideModal / addNotification recorders
//   - rpc: declare() backed by a script keyed by ubus method name
//
// Everything a module could reach as a bare global (localStorage, navigator,
// location, FormData) is passed as an extra factory parameter, so tests never
// mutate Node's globals and scenarios stay isolated from each other.

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const RESOURCES = path.resolve(__dirname, '..', 'htdocs', 'luci-static', 'resources');

function moduleFile(name) {
  return path.join(RESOURCES, name.replace(/\./g, '/') + '.js');
}

// Same scan as luci.js compileClass(): walk string literals from the top of
// the source; each one is either 'use strict' or a require statement, the
// first one that is neither ends the header.
function scanRequires(source) {
  const requirematch = /^require[ \t]+(\S+)(?:[ \t]+as[ \t]+([a-zA-Z_]\S*))?$/;
  const strictmatch = /^use[ \t]+strict$/;
  const deps = [];
  for (let i = 0, off = -1, prev = -1, quote = -1, comment = -1, esc = false; i < source.length; i++) {
    const chr = source.charCodeAt(i);
    if (esc) {
      esc = false;
    } else if (comment != -1) {
      if ((comment == 47 && chr == 10) || (comment == 42 && prev == 42 && chr == 47)) comment = -1;
    } else if ((chr == 42 || chr == 47) && prev == 47) {
      comment = chr;
    } else if (chr == 92) {
      esc = true;
    } else if (chr == quote) {
      const s = source.substring(off, i);
      const m = requirematch.exec(s);
      if (m) {
        deps.push({ name: m[1], as: m[2] || m[1].replace(/[^a-zA-Z0-9_]/g, '_') });
      } else if (!strictmatch.exec(s)) {
        break;
      }
      off = -1;
      quote = -1;
    } else if (quote == -1 && (chr == 34 || chr == 39)) {
      off = i + 1;
      quote = chr;
    }
    prev = chr;
  }
  return deps;
}

function makeClass() {
  let classIndex = 0;
  const Class = Object.assign(function () {}, {
    __name__: 'LuCI.baseclass',
    extend(properties) {
      const props = {
        __id__: { value: classIndex },
        __base__: { value: this.prototype },
        __name__: { value: properties.__name__ != null ? properties.__name__ : 'anonymous' + classIndex++ },
      };
      const ClassConstructor = function () {
        if (!(this instanceof ClassConstructor)) throw new TypeError('Constructor must not be called without "new"');
        if (Object.getPrototypeOf(this).hasOwnProperty('__init__')) {
          if (typeof this.__init__ != 'function') throw new TypeError('Class __init__ member is not a function');
          this.__init__.apply(this, arguments);
        } else {
          this.super('__init__', arguments);
        }
      };
      for (const key in properties)
        if (!props[key] && properties.hasOwnProperty(key)) props[key] = { value: properties[key], writable: true };
      ClassConstructor.prototype = Object.create(this.prototype, props);
      ClassConstructor.prototype.constructor = ClassConstructor;
      Object.assign(ClassConstructor, this);
      ClassConstructor.displayName = props.__name__.value + 'Class';
      return ClassConstructor;
    },
    singleton(properties, ...args) {
      return Class.extend(properties).instantiate(args);
    },
    instantiate(args) {
      return new (Function.prototype.bind.call(this, null, ...(args || [])))();
    },
    isSubclass(v) {
      return typeof v == 'function' && v.prototype instanceof this;
    },
    prototype: {
      varargs(args, offset, ...extra) {
        return extra.concat(Array.prototype.slice.call(args, offset));
      },
      // Walk the __base__ chain for `key` and call it; null when absent
      // (a class without __init__ ends up here from the constructor).
      super(key, callArgs) {
        let base = Object.getPrototypeOf(this).__base__;
        while (base) {
          if (Object.prototype.hasOwnProperty.call(base, key) && typeof base[key] == 'function')
            return base[key].apply(this, Array.isArray(callArgs) ? callArgs : Array.prototype.slice.call(callArgs || []));
          base = base.__base__;
        }
        return null;
      },
    },
  });
  return Class;
}

function makeDom(document) {
  const dom = {
    elem(e) {
      return e != null && typeof e == 'object' && typeof e.nodeType == 'number';
    },
    parse(s) {
      const tpl = document.createElement('template');
      tpl.innerHTML = s;
      return tpl.content.firstElementChild || tpl.content.firstChild;
    },
    attr(node, key, val) {
      if (!this.elem(node)) return null;
      let attr = null;
      if (typeof key == 'object' && key !== null) attr = key;
      else if (typeof key == 'string') (attr = {}), (attr[key] = val);
      for (key in attr) {
        if (!attr.hasOwnProperty(key) || attr[key] == null) continue;
        switch (typeof attr[key]) {
          case 'function':
            node.addEventListener(key, attr[key]);
            break;
          case 'object':
            node.setAttribute(key, JSON.stringify(attr[key]));
            break;
          default:
            node.setAttribute(key, attr[key]);
        }
      }
    },
    append(node, children) {
      if (Array.isArray(children)) {
        for (let i = 0; i < children.length; i++) {
          if (this.elem(children[i])) node.appendChild(children[i]);
          else if (children[i] !== null && children[i] !== undefined) node.appendChild(document.createTextNode('' + children[i]));
        }
        return node.lastChild;
      } else if (typeof children == 'function') {
        return this.append(node, children(node));
      } else if (this.elem(children)) {
        return node.appendChild(children);
      } else if (children !== null && children !== undefined) {
        node.innerHTML = '' + children;
        return node.lastChild;
      }
      return null;
    },
    content(node, children) {
      if (!this.elem(node)) return null;
      while (node.firstChild) node.removeChild(node.firstChild);
      return this.append(node, children);
    },
    create() {
      const html = arguments[0];
      let attr = arguments[1];
      let data = arguments[2];
      let elem;
      if (!(attr instanceof Object) || Array.isArray(attr)) (data = attr), (attr = null);
      if (Array.isArray(html)) {
        elem = document.createDocumentFragment();
        for (let i = 0; i < html.length; i++) elem.appendChild(this.create(html[i]));
      } else if (this.elem(html)) {
        elem = html;
      } else if (typeof html == 'string' && html.charCodeAt(0) === 60) {
        elem = this.parse(html);
      } else {
        elem = document.createElement(html);
      }
      if (!elem) return null;
      this.attr(elem, attr);
      this.append(elem, data);
      return elem;
    },
  };
  return dom;
}

// Scripted rpc fake. `scripts` is keyed by ubus method name; a value is
// returned as the reply, a function is called with (params, positionalArgs)
// and may return a value, a promise, or throw (→ rejection). A method listed
// in `undeclared` makes declare() return undefined, which is what an older
// rpc.js without that declaration looks like to the rest of the code.
function makeRpc(scripts, undeclared, calls, declared) {
  return {
    declare(options) {
      declared.push(options.method);
      if (undeclared.indexOf(options.method) !== -1) return undefined;
      const method = options.method;
      const paramNames = options.params || [];
      return function () {
        const args = Array.prototype.slice.call(arguments);
        const params = {};
        for (let i = 0; i < paramNames.length; i++) if (args[i] !== undefined) params[paramNames[i]] = args[i];
        calls.push({ method, object: options.object, params, args });
        const s = scripts[method];
        if (typeof s == 'function') {
          try {
            return Promise.resolve(s(params, args));
          } catch (e) {
            return Promise.reject(e);
          }
        }
        return Promise.resolve(s === undefined ? { success: true } : s);
      };
    },
  };
}

function makePoll() {
  const queue = [];
  return {
    queue,
    add(fn, interval) {
      if (typeof fn != 'function') throw new TypeError('Invalid argument to LuCI.poll.add()');
      for (const e of queue) if (e.fn === fn) return false;
      queue.push({ fn, i: interval >>> 0, r: true });
      return true;
    },
    remove(fn) {
      const i = queue.findIndex((e) => e.fn === fn);
      if (i === -1) return false;
      queue.splice(i, 1);
      return true;
    },
    start() {
      return true;
    },
    stop() {
      return true;
    },
    active() {
      return true;
    },
    // Test helper: run every poll registered with this interval.
    fire(interval) {
      return Promise.all(queue.filter((e) => e.i === interval).map((e) => e.fn()));
    },
  };
}

function makeUi(document, dom, records) {
  return {
    showModal(title, children, cls) {
      records.modals.push({ title, cls });
      const m = dom.create('div', { class: 'modal ' + (cls || '') }, children);
      document.body.appendChild(m);
      return m;
    },
    hideModal() {
      records.modals.push({ hidden: true });
    },
    addNotification(title, children, cls) {
      records.notifications.push({ title, cls });
      return dom.create('div', { class: 'alert-message ' + (cls || '') }, children);
    },
  };
}

// Build one isolated environment. opts:
//   rpc:        { ubus_method: reply | fn(params, args) }
//   undeclared: [ 'ubus_method', ... ]  methods rpc.js should appear not to declare
function createEnv(opts) {
  opts = opts || {};
  const jsdom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://192.168.1.1/cgi-bin/luci/admin/vpn/nym-vpn' });
  const { window } = jsdom;
  const { document } = window;
  const Class = makeClass();
  const dom = makeDom(document);
  const calls = [];
  const declared = [];
  const records = { modals: [], notifications: [], reloads: 0 };
  const poll = makePoll();
  const rpc = makeRpc(opts.rpc || {}, opts.undeclared || [], calls, declared);
  const ui = makeUi(document, dom, records);
  const view = Class.extend({
    __name__: 'LuCI.view',
    __init__() {},
    load() {},
    render() {},
    addFooter() {
      return null;
    },
  });
  const location = {
    href: window.location.href,
    reload() {
      records.reloads++;
    },
  };
  const modules = {};
  const builtins = { baseclass: Class, dom, poll, ui, rpc, view };

  const L = {
    env: { pollinterval: 5 },
    dom,
    poll,
    ui,
    bind(fn, self, ...args) {
      return Function.prototype.bind.apply(fn, [self].concat(args));
    },
    isObject(v) {
      return v != null && typeof v == 'object' && !Array.isArray(v);
    },
    toArray(v) {
      return v == null ? [] : Array.isArray(v) ? v : [v];
    },
    raise(type, fmt, ...args) {
      throw new Error(type + ': ' + fmt.replace(/%[sd]/g, () => String(args.shift())));
    },
    error(e) {
      throw e;
    },
    require(name) {
      return Promise.resolve(load(name, []));
    },
  };

  function load(name, from) {
    if (name in modules) return modules[name];
    if (name in builtins) return (modules[name] = builtins[name]);
    if (from.indexOf(name) !== -1) throw new Error('Circular dependency: ' + from.concat(name).join(' -> '));
    const file = moduleFile(name);
    if (!fs.existsSync(file)) throw new Error('Module not found: ' + name + ' (' + file + ')');
    const source = fs.readFileSync(file, 'utf8');
    const deps = scanRequires(source);
    const instances = deps.map((d) => load(d.name, from.concat(name)));
    const params = ['window', 'document', 'L', 'localStorage', 'navigator', 'location', 'FormData'].concat(deps.map((d) => d.as));
    let factory;
    try {
      factory = new Function(...params, source);
    } catch (e) {
      throw new Error('SyntaxError in ' + name + ': ' + e.message);
    }
    const _class = factory.apply(factory, [window, document, L, window.localStorage, window.navigator, location, window.FormData].concat(instances));
    if (!Class.isSubclass(_class)) throw new TypeError('"' + name + '" factory yields invalid constructor (must return baseclass.extend(...))');
    const instance = new _class();
    modules[name] = instance;
    return instance;
  }

  return { window, document, dom, E: dom.create.bind(dom), Class, poll, calls, declared, records, modules, require: (n) => load(n, []), jsdom };
}

module.exports = { createEnv, scanRequires, RESOURCES, moduleFile };
