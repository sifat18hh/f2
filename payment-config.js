
// Payment Gateway Configuration - PRODUCTION READY
// Replace with your actual API credentials before going live

const paymentConfig = {
    bkash: {
        // bKash Merchant API credentials (get from bKash merchant portal)
        // PRODUCTION: Get these from https://merchant.bkash.com/
        username: process.env.BKASH_USERNAME || 'your_bkash_username',
        password: process.env.BKASH_PASSWORD || 'your_bkash_password', 
        app_key: process.env.BKASH_APP_KEY || 'your_bkash_app_key',
        app_secret: process.env.BKASH_APP_SECRET || 'your_bkash_app_secret',
        base_url: process.env.BKASH_BASE_URL || 'https://tokenized.pay.bka.sh/v1.2.0-beta', // LIVE URL
        mode: process.env.BKASH_MODE || 'live' // 'sandbox' or 'live'
    },
    
    paypal: {
        // PayPal API credentials (get from PayPal developer portal)
        client_id: process.env.PAYPAL_CLIENT_ID || 'your_paypal_client_id',
        client_secret: process.env.PAYPAL_CLIENT_SECRET || 'your_paypal_client_secret',
        mode: process.env.PAYPAL_MODE || 'sandbox' // 'sandbox' or 'live'
    },
    
    bank: {
        // Bank API credentials (contact your bank for API access)
        api_key: process.env.BANK_API_KEY || 'your_bank_api_key',
        bank_code: process.env.BANK_CODE || 'your_bank_code',
        mode: process.env.BANK_MODE || 'test'
    },
    
    crypto: {
        // Crypto payment gateway (e.g., Coinbase Commerce, BitPay)
        api_key: process.env.CRYPTO_API_KEY || 'your_crypto_api_key',
        webhook_secret: process.env.CRYPTO_WEBHOOK_SECRET || 'your_webhook_secret',
        supported_currencies: ['BTC', 'ETH', 'USDT', 'BNB']
    }
};

module.exports = paymentConfig;
