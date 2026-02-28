'use strict';
'require baseclass';

return baseclass.extend({
    data: {
        'AE': { flag: '🇦🇪', name: 'United Arab Emirates' },
        'AL': { flag: '🇦🇱', name: 'Albania' },
        'AM': { flag: '🇦🇲', name: 'Armenia' },
        'AR': { flag: '🇦🇷', name: 'Argentina' },
        'AT': { flag: '🇦🇹', name: 'Austria' },
        'AU': { flag: '🇦🇺', name: 'Australia' },
        'BE': { flag: '🇧🇪', name: 'Belgium' },
        'BG': { flag: '🇧🇬', name: 'Bulgaria' },
        'BH': { flag: '🇧🇭', name: 'Bahrain' },
        'BO': { flag: '🇧🇴', name: 'Bolivia' },
        'BR': { flag: '🇧🇷', name: 'Brazil' },
        'CA': { flag: '🇨🇦', name: 'Canada' },
        'CH': { flag: '🇨🇭', name: 'Switzerland' },
        'CL': { flag: '🇨🇱', name: 'Chile' },
        'CO': { flag: '🇨🇴', name: 'Colombia' },
        'CR': { flag: '🇨🇷', name: 'Costa Rica' },
        'CY': { flag: '🇨🇾', name: 'Cyprus' },
        'CZ': { flag: '🇨🇿', name: 'Czech Republic' },
        'DE': { flag: '🇩🇪', name: 'Germany' },
        'EC': { flag: '🇪🇨', name: 'Ecuador' },
        'EE': { flag: '🇪🇪', name: 'Estonia' },
        'ES': { flag: '🇪🇸', name: 'Spain' },
        'FI': { flag: '🇫🇮', name: 'Finland' },
        'FR': { flag: '🇫🇷', name: 'France' },
        'GB': { flag: '🇬🇧', name: 'United Kingdom' },
        'GR': { flag: '🇬🇷', name: 'Greece' },
        'GT': { flag: '🇬🇹', name: 'Guatemala' },
        'HK': { flag: '🇭🇰', name: 'Hong Kong' },
        'HR': { flag: '🇭🇷', name: 'Croatia' },
        'HU': { flag: '🇭🇺', name: 'Hungary' },
        'ID': { flag: '🇮🇩', name: 'Indonesia' },
        'IE': { flag: '🇮🇪', name: 'Ireland' },
        'IL': { flag: '🇮🇱', name: 'Israel' },
        'IN': { flag: '🇮🇳', name: 'India' },
        'IS': { flag: '🇮🇸', name: 'Iceland' },
        'IT': { flag: '🇮🇹', name: 'Italy' },
        'JP': { flag: '🇯🇵', name: 'Japan' },
        'KH': { flag: '🇰🇭', name: 'Cambodia' },
        'KR': { flag: '🇰🇷', name: 'South Korea' },
        'LT': { flag: '🇱🇹', name: 'Lithuania' },
        'LV': { flag: '🇱🇻', name: 'Latvia' },
        'MD': { flag: '🇲🇩', name: 'Moldova' },
        'MK': { flag: '🇲🇰', name: 'North Macedonia' },
        'MX': { flag: '🇲🇽', name: 'Mexico' },
        'MY': { flag: '🇲🇾', name: 'Malaysia' },
        'NG': { flag: '🇳🇬', name: 'Nigeria' },
        'NL': { flag: '🇳🇱', name: 'Netherlands' },
        'NO': { flag: '🇳🇴', name: 'Norway' },
        'NZ': { flag: '🇳🇿', name: 'New Zealand' },
        'PE': { flag: '🇵🇪', name: 'Peru' },
        'PK': { flag: '🇵🇰', name: 'Pakistan' },
        'PL': { flag: '🇵🇱', name: 'Poland' },
        'PT': { flag: '🇵🇹', name: 'Portugal' },
        'RO': { flag: '🇷🇴', name: 'Romania' },
        'RS': { flag: '🇷🇸', name: 'Serbia' },
        'RU': { flag: '🇷🇺', name: 'Russia' },
        'SE': { flag: '🇸🇪', name: 'Sweden' },
        'SG': { flag: '🇸🇬', name: 'Singapore' },
        'SI': { flag: '🇸🇮', name: 'Slovenia' },
        'SK': { flag: '🇸🇰', name: 'Slovakia' },
        'TR': { flag: '🇹🇷', name: 'Turkey' },
        'TW': { flag: '🇹🇼', name: 'Taiwan' },
        'UA': { flag: '🇺🇦', name: 'Ukraine' },
        'US': { flag: '🇺🇸', name: 'United States' },
        'VN': { flag: '🇻🇳', name: 'Vietnam' },
        'ZA': { flag: '🇿🇦', name: 'South Africa' }
    },

    getDisplay: function(code) {
        if (!code || code === 'random' || code === 'Random') {
            return { flag: '🌐', name: 'Random' };
        }
        return this.data[code] || { flag: '🏳️', name: code };
    },

    getFlag: function(code) {
        if (!code) return '🌐';
        return (this.data[code] || {}).flag || '🌐';
    }
});
