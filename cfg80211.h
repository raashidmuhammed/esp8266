#define RATETAB_ENT(_rate, _rateid, _flags) \
        {                                                               \
                .bitrate        = (_rate),                              \
                .hw_value       = (_rateid),                            \
                .flags          = (_flags),                             \
        }


#define CHAN2G(_channel, _freq, _flags) {		      \
        .band                   = NL80211_BAND_2GHZ,          \
        .center_freq            = (_freq),                      \
        .hw_value               = (_channel),                   \
        .flags                  = (_flags),                     \
        .max_antenna_gain       = 0,                            \
        .max_power              = 30,                           \
}

#define CHAN5G(_channel, _flags) {                              \
        .band                   = NL80211_BAND_5GHZ,          \
        .center_freq            = 5000 + (5 * (_channel)),      \
        .hw_value               = (_channel),                   \
        .flags                  = (_flags),                     \
        .max_antenna_gain       = 0,                            \
        .max_power              = 30,                           \
}

static struct ieee80211_rate esp_rates[] = {
        RATETAB_ENT(10,  0x1,   0),
        RATETAB_ENT(20,  0x2,   0),
        RATETAB_ENT(55,  0x4,   0),
        RATETAB_ENT(110, 0x8,   0),
        RATETAB_ENT(60,  0x10,  0),
        RATETAB_ENT(90,  0x20,  0),
        RATETAB_ENT(120, 0x40,  0),
        RATETAB_ENT(180, 0x80,  0),
        RATETAB_ENT(240, 0x100, 0),
        RATETAB_ENT(360, 0x200, 0),
        RATETAB_ENT(480, 0x400, 0),
        RATETAB_ENT(540, 0x800, 0),
};

#define esp_a_rates             (esp_rates + 4)
#define esp_a_rates_size        8
#define esp_g_rates             (esp_rates + 0)
#define esp_g_rates_size        12

static struct ieee80211_channel esp_2ghz_channels[] = {
        CHAN2G(1, 2412, 0),
        CHAN2G(2, 2417, 0),
        CHAN2G(3, 2422, 0),
        CHAN2G(4, 2427, 0),
        CHAN2G(5, 2432, 0),
        CHAN2G(6, 2437, 0),
        CHAN2G(7, 2442, 0),
        CHAN2G(8, 2447, 0),
        CHAN2G(9, 2452, 0),
        CHAN2G(10, 2457, 0),
        CHAN2G(11, 2462, 0),
        CHAN2G(12, 2467, 0),
        CHAN2G(13, 2472, 0),
        CHAN2G(14, 2484, 0),
};

static struct ieee80211_channel esp_5ghz_a_channels[] = {
        CHAN5G(34, 0),          CHAN5G(36, 0),
        CHAN5G(38, 0),          CHAN5G(40, 0),
        CHAN5G(42, 0),          CHAN5G(44, 0),
        CHAN5G(46, 0),          CHAN5G(48, 0),
        CHAN5G(52, 0),          CHAN5G(56, 0),
        CHAN5G(60, 0),          CHAN5G(64, 0),
        CHAN5G(100, 0),         CHAN5G(104, 0),
        CHAN5G(108, 0),         CHAN5G(112, 0),
        CHAN5G(116, 0),         CHAN5G(120, 0),
        CHAN5G(124, 0),         CHAN5G(128, 0),
        CHAN5G(132, 0),         CHAN5G(136, 0),
        CHAN5G(140, 0),         CHAN5G(149, 0),
        CHAN5G(153, 0),         CHAN5G(157, 0),
        CHAN5G(161, 0),         CHAN5G(165, 0),
        CHAN5G(184, 0),         CHAN5G(188, 0),
        CHAN5G(192, 0),         CHAN5G(196, 0),
        CHAN5G(200, 0),         CHAN5G(204, 0),
        CHAN5G(208, 0),         CHAN5G(212, 0),
        CHAN5G(216, 0),
};


static struct ieee80211_supported_band esp_band_2ghz = {
        .channels = esp_2ghz_channels,
        .n_channels = ARRAY_SIZE(esp_2ghz_channels),
        .bitrates = esp_g_rates,
        .n_bitrates = esp_g_rates_size,
};

static struct ieee80211_supported_band esp_band_5ghz = {
        .channels = esp_5ghz_a_channels,
        .n_channels = ARRAY_SIZE(esp_5ghz_a_channels),
        .bitrates = esp_a_rates,
        .n_bitrates = esp_a_rates_size,
};
