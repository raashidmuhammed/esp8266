#include <linux/module.h>
#include <linux/tty.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <net/cfg80211.h>
#include "crc16.h"
#include "esp8266.h"
#include "cfg80211.h"

#define N_ESP8266 26

MODULE_ALIAS_LDISC(N_ESP8266);
MODULE_DESCRIPTION("ESP8266 driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Raashid Muhammed <raashidmuhammed@zilogic.com>");


struct esp8266 {
	struct tty_struct	*tty;
	struct net_device	*dev;
	struct wiphy		*wiphy;
	struct wireless_dev	wdev;
	spinlock_t		lock;
	struct work_struct	tx_work; 	/* Flush xmit buffer */

	uint8_t			xbuff[BUF_SIZE];
	uint8_t			*xhead;      	/* Pointer to next xmit byte */
	int			xleft;		/* Bytes left in xmit queue */
	unsigned int		xpos;

	uint8_t			rbuff[BUF_SIZE];
	unsigned int		rlen;

	uint8_t			msg_type;
	uint8_t			data[BUF_SIZE];
	unsigned int		len;
	uint16_t		crc;
};

static int serial_write(struct esp8266 *esp, uint8_t byte)
{
	int actual;

	esp->xbuff[esp->xpos] = byte;
	esp->xpos += 1;

	if (byte == SERIAL_STOP_BYTE) {
		set_bit(TTY_DO_WRITE_WAKEUP, &esp->tty->flags);
		actual = esp->tty->ops->write(esp->tty, esp->xbuff, esp->xpos);
		if (actual < 0) {
			printk("esp8266: Serial write failed\n");
			return -1;
		}

		/* Handling partial writes */
		esp->xleft = esp->xpos - actual;
		esp->xhead = esp->xbuff + actual;
		esp->dev->stats.tx_bytes += actual;

		esp->xpos = 0;
	}
	return 0;
}

static int stuff_tx_byte(struct esp8266 *esp, uint8_t byte)
{
	int ret;

	if ((byte == SERIAL_STOP_BYTE) || (byte == SERIAL_ESC_BYTE)) {
		ret = serial_write(esp, SERIAL_ESC_BYTE);
		if (ret < 0)
			return -1;

		ret = serial_write(esp, byte ^ SERIAL_XOR_BYTE);
		if (ret < 0)
			return -1;
	} else {
		ret = serial_write(esp, byte);
		if (ret < 0)
			return -1;
	}
	return 0;
}

static int byte_destuff_packet(struct esp8266 *esp)
{
	int flag = 0;
	int i = 0;
	int j = 0;


	while (i < esp->rlen) {
		if (esp->rbuff[i] == SERIAL_ESC_BYTE) {
			flag = 1;
			i++;
			continue;
		}

		if (j == (MAX_FRAME_LEN / 2))
			return -1;

		if (flag == 1) {
			esp->rbuff[j++] = esp->rbuff[i++]
				^ SERIAL_XOR_BYTE;
			flag = 0;
			continue;
		}
		esp->rbuff[j++] = esp->rbuff[i++];
	}

	esp->rlen = j;

	return 0;
}

static int parse_data(struct esp8266 *esp)
{

	uint16_t crc_l;

	if (esp->rlen < MIN_BYTE_EXPECTED)
		return -1;

	esp->crc = esp->rbuff[--(esp->rlen)];
	crc_l = esp->rbuff[--(esp->rlen)];
	esp->crc <<= 8;
	esp->crc = esp->crc | crc_l;

	return 0;
}

static int check_data_integrity(struct esp8266 *esp)
{
	uint16_t cal_crc;

	cal_crc = crc16_ccitt_block(esp->rbuff, esp->rlen);
	if (esp->crc != cal_crc)
		return -3;

	return 0;
}

static int crc_stuff_tx_byte(struct esp8266 *esp, uint8_t byte)
{
	int ret;

	crc16_ccitt_update(&esp->crc, byte);
	ret = stuff_tx_byte(esp, byte);

	return ret;
}

static int esp_read(struct esp8266 *esp)
{
	if (byte_destuff_packet(esp) < 0) {
		printk("esp8266: destuff error\n");
		return -1;
	}

	if (parse_data(esp) < 0){
		printk("esp8266: parse_data error\n");
		return -1;
	}

	if (check_data_integrity(esp)) {
		printk("esp8266: crc failure\n");
		esp->dev->stats.rx_crc_errors++;
		return -1;
	}

	return 0;
}

static int esp_send(struct esp8266 *esp)
{
	int ret;
	int index;

	esp->crc = 0;

	ret = crc_stuff_tx_byte(esp, esp->msg_type);
	if (ret < 0)
		return -1;

	for(index = 0; index < esp->len; index++){
		ret = crc_stuff_tx_byte(esp, esp->data[index]);
		if (ret < 0)
			return -1;
	}
	ret = stuff_tx_byte(esp, LSB(esp->crc));
	if (ret < 0)
		return -1;

	ret = stuff_tx_byte(esp, MSB(esp->crc));
	if (ret < 0)
		return -1;

	ret = serial_write(esp, SERIAL_STOP_BYTE);
	if (ret < 0)
		return -1;

	return 0;
}


static int configure_esp(struct esp8266 *esp, uint8_t msg_type, uint8_t mode)
{
	esp->msg_type = msg_type;
	esp->data[0] = mode;
	esp->len = 1;
	if (esp_send(esp) < 0)
		return -1;

	return 0;
}

static void generate_connect_header(struct msg_station_conf *conf, char *ssid, char *password)
{
	memset(conf, 0, sizeof(struct msg_station_conf));
	conf->msg_type = MSG_STATION_CONF_SET;
	conf->ssid_len = strlen(ssid);
	conf->password_len = strlen(password);
	memcpy(&conf->ssid, ssid, conf->ssid_len);
	memcpy(&conf->password, password, conf->password_len);
}

static int espnet_init(struct net_device *dev)
{
	struct esp8266 *esp = netdev_priv(dev);
	struct msg_station_conf conf;
	char ssid[32] = "Zilogic Quiz";
	char password[64] = "zilogic123";

	if (configure_esp(esp, MSG_WIFI_SLEEP_MODE_SET, WIFI_SLEEP_NONE) < 0) {
		printk("esp8266: Error Initializing Sleep Mode");
		return -1;
	}
	if (configure_esp(esp, MSG_SET_FORWARDING_MODE, FORWARDING_MODE_ETHER) < 0) {
		printk("esp8266: Error Initializing Forwarding Mode");
		return -1;
	}

	if (configure_esp(esp, MSG_WIFI_MODE_SET, DEVICE_MODE_STAION) < 0) {
		printk("esp8266: Error Initializing Device Mode");
		return -1;
	}

	/* fixme: establishing connection with AP */
	generate_connect_header(&conf, ssid, password);
	esp->msg_type = conf.msg_type;
	memmove(esp->data, &conf, sizeof(struct msg_station_conf));
	esp->len = sizeof(struct msg_station_conf) - 1;
	memmove(esp->data, &esp->data[1], esp->len);
	esp_send(esp);

	esp->len = 0;
	esp->rlen = 0;

	return 0;
}

/* Netdevice DOWN -> UP routine */
static int espnet_open(struct net_device *dev)
{
	struct esp8266 *esp = netdev_priv(dev);

	if (esp->tty == NULL) {
		printk("esp8266: No TTY device\n");
		return -ENODEV;
	}

	netif_start_queue(dev);

	return 0;
}

static netdev_tx_t espnet_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct esp8266 *esp = netdev_priv(dev);

	/* fixme: should mtu check be done at this point */

	spin_lock(&esp->lock);
	if (!netif_running(dev)) {
		printk(KERN_WARNING "esp8266: %s: xmit: iface is down\n", dev->name);
		goto out;
	}
	if (esp->tty == NULL) {
		goto out;
	}

	netif_stop_queue(esp->dev);
	dev->stats.tx_bytes += skb->len;
	esp->msg_type = MSG_ETHER_PACKET;
	esp->len = skb->len;
	memmove(esp->data, skb->data, skb->len);
	esp_send(esp);

	esp->len = 0;

out:
	spin_unlock(&esp->lock);
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}


/* Netdevice UP -> DOWN routine */
static int espnet_close(struct net_device *dev)
{
	struct esp8266 *esp = netdev_priv(dev);

	if (esp->tty) {
		/* TTY discipline is running. */
		clear_bit(TTY_DO_WRITE_WAKEUP, &esp->tty->flags);
	}
	netif_stop_queue(dev);

	return 0;
}

static void esp_transmit(struct work_struct *work)
{
	struct esp8266 *esp = container_of(work, struct esp8266, tx_work);
	int actual;

	spin_lock_bh(&esp->lock);
	/* First make sure we're connected. */
	if (!esp->tty || !netif_running(esp->dev)) {
		spin_unlock_bh(&esp->lock);
		return;
	}

	if (esp->xleft <= 0) {
		/* Now serial buffer is almost free & we can start
		 * transmission of another packet */
		esp->dev->stats.tx_packets++;
		clear_bit(TTY_DO_WRITE_WAKEUP, &esp->tty->flags);
		spin_unlock_bh(&esp->lock);
		netif_wake_queue(esp->dev);
		return;
	}

	actual = esp->tty->ops->write(esp->tty, esp->xhead, esp->xleft);
	esp->xleft -= actual;
	esp->xhead += actual;
	spin_unlock_bh(&esp->lock);
}

static int esp_cfg80211_scan(struct wiphy *wiphy,
			     struct cfg80211_scan_request *request)
{
	printk("esp8266: esp_scan called\n");
	struct cfg80211_scan_info info = {};
	struct cfg80211_bss *bss;
	struct ieee80211_channel *channel;
	u32 freq;
	s32 signal = 1;
	u64 timestamp = 1;
	u16 capability = 1;
	u32 beacon_period = 1;
	int len = 1, ret, ie_len = 10;
	u8 bssid[8] =  "Hello";
	u8 ie_buf[34];
	ie_buf[0] = 3;
	ie_buf[1] = 4;

	freq = ieee80211_channel_to_frequency(1, NL80211_BAND_2GHZ);
	printk("esp8266: freq: %d\n", freq);
	channel = ieee80211_get_channel(wiphy, freq);
	if (!channel) {
		printk("esp8266: No channel\n");
		return -1;
	}

	bss = cfg80211_inform_bss(wiphy, channel, CFG80211_BSS_FTYPE_UNKNOWN,
			    bssid, timestamp, capability, beacon_period,
			    ie_buf, ie_len, signal, GFP_KERNEL);
	//	cfg80211_put_bss(wiphy, bss);
	cfg80211_scan_done(request, &info);
	return 0;
}

static int esp_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
			     struct cfg80211_connect_params *sme)
{
	printk("esp8266: esp_connect called\n");
	return 0;
}

static int esp_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
				   struct cfg80211_connect_params *sme)
{
	printk("esp8266: esp_disconnect callled\n");


	return 0;
}

static struct cfg80211_ops esp_cfg80211_ops = {
	.scan		= esp_cfg80211_scan,
	.connect	= esp_cfg80211_connect,
	.disconnect	= esp_cfg80211_disconnect,
};

static const struct net_device_ops esp_netdev_ops = {
	.ndo_init		= espnet_init,
	.ndo_open               = espnet_open,
	.ndo_stop               = espnet_close,
	.ndo_start_xmit         = espnet_xmit,
};

static void esp_free_netdev(struct net_device *dev)
{
	free_netdev(dev);
}

static void esp_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops		= &esp_netdev_ops;
	dev->destructor		= esp_free_netdev;
}

int wiphy_init(struct esp8266 *esp)
{
	int ret;
	struct wiphy *wiphy = esp->wiphy;

	//	wiphy->mgmt_stypes =
	//	wiphy->max_remain_on_channel_duration = 5000;

	/* set device pointer for wiphy */
	set_wiphy_dev(wiphy, esp->tty->dev);

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

	/* max num of ssids that can be probed during scanning */
	wiphy->max_scan_ssids = 128;

	wiphy->max_scan_ie_len = 1000; /* FIX: what is correct limit? */

	//	wiphy->available_antennas_tx = ar->hw.tx_ant;
	//	wiphy->available_antennas_rx = ar->hw.rx_ant;

	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;	 /* fixme: */

	wiphy->bands[NL80211_BAND_2GHZ] = &esp_band_2ghz;
	wiphy->bands[NL80211_BAND_5GHZ] = &esp_band_5ghz;
	// *fixme: required?	wiphy->max_sched_scan_ssids
	/* fixme: required? wiphy->flags ? */
	/* fixme: wiphy->probe_resp_offload */

	ret = wiphy_register(wiphy);
	if (ret < 0) {
		printk("esp8266: couldn't register wiphy device");
		wiphy_free(esp->wiphy);
		return -1;
	}

	return 0;
}

static int esptty_open(struct tty_struct *tty)
{
	int err;
	char name[IFNAMSIZ];
	struct esp8266 *esp;
	/*fixme: name should be netdev */
	struct net_device *dev = NULL;
	struct wiphy *wiphy;
	unsigned char mac_addr[] = {0x5c, 0xcf, 0x7f, 0x0b, 0x9c, 0xb6};

	sprintf(name, "esp%d", 0);
	dev = alloc_netdev(sizeof(*esp), name, NET_NAME_UNKNOWN, esp_setup);
	if (!dev) {
		return -1;
	}

	wiphy = wiphy_new(&esp_cfg80211_ops, sizeof(struct esp8266));
	if (!wiphy) {
		printk("esp8266: couldn't allocate wiphy device");
		return -1;
	}

	/* fixme: get mac from esp before setting */
	ether_addr_copy(dev->dev_addr, mac_addr);
	dev->addr_assign_type = NET_ADDR_PERM;

	esp = netdev_priv(dev);
	esp->dev = dev;
	esp->tty = tty;
	esp->wiphy = wiphy;
	esp->dev->ieee80211_ptr = &esp->wdev;
	esp->wdev.wiphy = wiphy;
	esp->wdev.iftype = NL80211_IFTYPE_STATION;
	esp->wdev.netdev = dev;
	SET_NETDEV_DEV(dev, wiphy_dev(esp->wiphy));
	esp->len = 0;
	spin_lock_init(&esp->lock);
	INIT_WORK(&esp->tx_work, esp_transmit);
	tty->disc_data = esp;

	err = wiphy_init(esp);
	if (err) {
		return err;
	}

	printk("wiphy registration complete\n");

	err = register_netdev(esp->dev);
	if (err) {
		printk("Netdevice registration failed.\n");
		esp->tty = NULL;
		tty->disc_data = NULL;
		return err;
	}

	tty->receive_room = 65536; /* Enables receive */

	return 0;
}

static void esp_forward(struct esp8266 *esp)
{
	struct sk_buff *skb;

	esp->dev->stats.rx_bytes += esp->rlen - 1;
	skb = dev_alloc_skb(esp->rlen - 1);
	if (skb == NULL) {
		printk(KERN_WARNING "%s: memory squeeze, dropping packet.\n", esp->dev->name);
		esp->dev->stats.rx_dropped++;
		return;
	}
	skb->dev = esp->dev;
	memcpy(skb_put(skb, esp->rlen - 1), &esp->rbuff[1], esp->rlen - 1);
	skb->protocol = eth_type_trans(skb, esp->dev);
	netif_rx_ni(skb);
	esp->dev->stats.rx_packets++;
}

static void esptty_receive_buf(struct tty_struct *tty, const unsigned char *cp,
			       char *fp, int count)
{
	struct esp8266 *esp = tty->disc_data;
	int index = 0;
	int ret;

	/* Read the characters out of the buffer */
	while (count--) {
		if (fp && *fp++) {
			cp++;
			printk("esp8266: Parity Errors\n");
			continue;
		}
		esp->rbuff[esp->rlen] = *(cp + index);
		if (esp->rbuff[esp->rlen] == SERIAL_STOP_BYTE) {
			ret = esp_read(esp);
			if (ret < 0)
				printk("esp8266: esp receive error\n");

			if (esp->rbuff[0] == MSG_ETHER_PACKET)
				esp_forward(esp);
			esp->rlen = -1;
		}

		index++;
		esp->rlen++;
	}
}

/*
 * Called by the driver when there's room for more data.
 * Schedule the transmit.
 */
static void esptty_write_wakeup(struct tty_struct *tty)
{
	struct esp8266 *esp = tty->disc_data;

	schedule_work(&esp->tx_work);
}

static void esptty_close(struct tty_struct *tty)
{
	struct esp8266 *esp = (struct esp8266 *) tty->disc_data;

	tty->disc_data = NULL;
	esp->tty = NULL;
	flush_work(&esp->tx_work);
	unregister_netdev(esp->dev);
	wiphy_unregister(esp->wiphy);
}


static struct tty_ldisc_ops esp8266_ldisc = {
	.owner		= THIS_MODULE,
	.magic		= TTY_LDISC_MAGIC,
	.name		= "n_esp",
	.open		= esptty_open,
	.close		= esptty_close,
	.receive_buf 	= esptty_receive_buf,
	.write_wakeup	= esptty_write_wakeup,
};

static int __init esp8266_init(void)
{
	int status;

	pr_info("esp8266: ESP8266 network driver\n");

	status = tty_register_ldisc(N_ESP8266, &esp8266_ldisc);
	if (status) {
		printk(KERN_ERR "esp8266: can't register line discipline\n");
	}
	return status;
}

static void __exit esp8266_exit(void)
{
	int ret;

	ret = tty_unregister_ldisc(N_ESP8266);
	if (ret)
		printk(KERN_ERR "esp8266: can't unregister ldisc (err %d)\n", ret);
}

module_init(esp8266_init);
module_exit(esp8266_exit);
