"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var jssha_1 = __importDefault(require("jssha"));
var TOTP = /** @class */ (function () {
    function TOTP() {
    }
    TOTP.get = function (secret, expiry, length, now) {
        if (expiry === void 0) { expiry = 30; }
        if (length === void 0) { length = 6; }
        if (now === void 0) { now = new Date().getTime(); }
        var key = this.base32tohex(secret);
        var epoch = Math.round(now / 1000.0);
        var time = this.leftpad(this.dec2hex(Math.floor(epoch / expiry)), 16, "0");
        var shaObj = new jssha_1.default("SHA-1", "HEX");
        shaObj.setHMACKey(key, "HEX");
        shaObj.update(time);
        var hmac = shaObj.getHMAC("HEX");
        if (hmac === "KEY MUST BE IN BYTE INCREMENTS") {
            throw new Error("hex key must be in byte increments");
        }
        var offset = this.hex2dec(hmac.substring(hmac.length - 1));
        var otp = (this.hex2dec(hmac.substr(offset * 2, 8)) & this.hex2dec("7fffffff")) + "";
        if (otp.length > length) {
            otp = otp.substr(otp.length - length, length);
        }
        else {
            otp = this.leftpad(otp, length, "0");
        }
        return otp;
    };
    TOTP.base32tohex = function (base32) {
        var base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = "";
        var hex = "";
        var val;
        var chunk = "";
        for (var i = 0; i < base32.length; i++) {
            val = base32chars.indexOf(base32.charAt(i).toUpperCase());
            bits += this.leftpad(val.toString(2), 5, "0");
        }
        for (var i = 0; i < bits.length; i += 4) {
            chunk = bits.substr(i, 4);
            hex = hex + parseInt(chunk, 2).toString(16);
        }
        return hex;
    };
    TOTP.leftpad = function (str, len, pad) {
        if (len + 1 >= str.length) {
            str = Array(len + 1 - str.length).join(pad) + str;
        }
        return str;
    };
    TOTP.dec2hex = function (s) {
        return (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
    };
    TOTP.hex2dec = function (s) {
        return parseInt(s, 16);
    };
    return TOTP;
}());
exports.default = TOTP;
//# sourceMappingURL=TOTP.js.map