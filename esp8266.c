#include <linux/module.h>
#include <linux/tty.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include "crc16.h"
#include "esp8266.h"

#define N_ESP8266 26

MODULE_ALIAS_LDISC(N_ESP8266);
MODULE_DESCRIPTION("ESP8266 driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Raashid Muhammed <raashidmuhammed@zilogic.com>");


struct esp8266 {
	int			magic; /* fixme: Needs to added to code */

	struct tty_struct	*tty;
	struct net_device	*dev;

	uint8_t			xbuff[4080];
	uint8_t			xpos;
	uint8_t			xlen;

	uint8_t			msg_type;
	uint8_t			data[BUF_SIZE];
	uint8_t			len;
	uint16_t		crc;

	unsigned long 		flags;
#define ESPF_ERROR		1	/* Parity error, etc. */
};


static void print_buf(uint8_t *buf, uint8_t len)
{
	int index;

	for(index = 0; index < len; index++)
		printk(KERN_CONT "%02X", buf[index]);
	printk("\n");
}

static void print_msg(struct esp8266 *esp)
{
	int index;

	printk(KERN_CONT "%02X,", esp->msg_type);

	for(index = 0; index < esp->len; index++)
		printk(KERN_CONT "%02X", esp->data[index]);
	printk("\n");
}

/* fixme: Give proper function name */
static int byte_send(struct esp8266 *esp, uint8_t byte)
{
	int bytes;

	esp->xbuff[esp->xpos] = byte;
	esp->xpos += 1;

	if ((esp->xpos == MAX_TX_BUF_SIZE) || (byte == SERIAL_STOP_BYTE)) {
		bytes = esp->tty->ops->write(esp->tty, esp->xbuff, esp->xpos);
		if (bytes < 0)
			return -1;

		printk("Tx frame: ");
		print_buf(esp->xbuff, esp->xpos);

		esp->xpos = 0;
	}
	return 0;
}

static int stuff_tx_byte(struct esp8266 *esp, uint8_t byte)
{
	int ret;

	if ((byte == SERIAL_STOP_BYTE) || (byte == SERIAL_ESC_BYTE)) {
		ret = byte_send(esp, SERIAL_ESC_BYTE);
		if (ret < 0)
			return -1;

		ret = byte_send(esp, byte ^ SERIAL_XOR_BYTE);
		if (ret < 0)
			return -1;
	} else {
		ret = byte_send(esp, byte);
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


	while (i < esp->len) {
		if (esp->data[i] == SERIAL_ESC_BYTE) {
			flag = 1;
			i++;
			continue;
		}

		if (j == (MAX_FRAME_LEN / 2))
			return -1;

		if (flag == 1) {
			esp->data[j++] = esp->data[i++]
				^ SERIAL_XOR_BYTE;
			flag = 0;
			continue;
		}
		esp->data[j++] = esp->data[i++];
	}

	esp->len = j;

	return 0;
}

static int parse_data(struct esp8266 *esp)
{

	uint16_t crc_l;

	if (esp->len < MIN_BYTE_EXPECTED)
		return -1;

	esp->msg_type = esp->data[0];

	esp->crc = esp->data[--(esp->len)];
	crc_l = esp->data[--(esp->len)];
	esp->crc <<= 8;
	esp->crc = esp->crc | crc_l;

	return 0;
}

static int check_data_integrity(struct esp8266 *esp)
{
	uint16_t cal_crc;

	cal_crc = crc16_ccitt_block(esp->data, esp->len);

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
		printk("destuff error\n");
		return -1;
	}


	if (parse_data(esp) < 0){
		printk("parse_data error\n");
		return -1;
	}


	if (check_data_integrity(esp)) {
		printk("crc failure\n");
		/* fixme: set crc failures */
		return -1;
	}

	memmove(esp->data, &esp->data[1], esp->len - 1);
	esp->len = esp->len - 1;

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

	ret = byte_send(esp, SERIAL_STOP_BYTE);
	if (ret < 0)
		return -1;

	return 0;
}


static int espnet_init(struct net_device *dev)
{
	printk("esp8266: espnet_init called");

	struct esp8266 *esp = netdev_priv(dev);

	esp->msg_type = MSG_ECHO_REQUEST;
	esp->data[0] = 0xde;
	esp->data[1] = 0xad;
	esp->data[2] = 0xbe;
	esp->data[3] = 0xef;
	esp->len = 4;

	esp_send(esp);

	return 0;
}

/* Netdevice DOWN -> UP routine */
static int espnet_open(struct net_device *dev)
{
	printk("esp8266: espnet_open called\n");

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
	printk("esp8266: espnet_xmit called\n");

	return NETDEV_TX_OK;
}

static int espnet_change_mtu(struct net_device *dev, int new_mtu)
{
	return 0;
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

static const struct net_device_ops esp_netdev_ops = {
	.ndo_init		= espnet_init,
	.ndo_open               = espnet_open,
	.ndo_stop               = espnet_close,
	.ndo_start_xmit         = espnet_xmit,
	.ndo_change_mtu         = espnet_change_mtu,
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

	dev->mtu		= 1500;
}

static int esptty_open(struct tty_struct *tty)
{
	int err;
	char name[IFNAMSIZ];
	struct esp8266 *esp;
	struct net_device *dev = NULL;
	unsigned char mac_addr[] = {0x5c, 0xcf, 0x7f, 0x0b, 0x9c, 0xb6};

	rtnl_lock();

	esp = tty->disc_data;
	sprintf(name, "esp%d", 0);
	dev = alloc_netdev(sizeof(*esp), name, NET_NAME_UNKNOWN, esp_setup);
	if (!dev) {
		rtnl_unlock();
		return -1;
	}

	ether_addr_copy(dev->dev_addr, mac_addr);
	ether_addr_copy(dev->perm_addr, mac_addr);

	esp = netdev_priv(dev);
	/* fixme: add magic check here */
	esp->dev = dev;
	esp->tty = tty;
	tty->disc_data = esp;

	err = register_netdevice(esp->dev);
	if (err) {
		printk("Netdevice registration failed.\n");
		esp->tty = NULL;
		tty->disc_data = NULL;
		rtnl_unlock();
		return err;
	}

	rtnl_unlock();

	tty->receive_room = 65536; /* Enables receive */

	return 0;
}

static void esptty_receive_buf(struct tty_struct *tty, const unsigned char *cp,
			       char *fp, int count)
{
	printk("esp8266: esptty_receive_buf called\n");

	struct esp8266 *esp = tty->disc_data;
	int index = 0;
	int ret;

	/* fixme: Add magic no check */

	/* fixme: copying data is unnecessary */
	esp->len = count - 1 /* Exclude end of frame */;

	/* Read the characters out of the buffer */
	while (count--) {
		if (fp && *fp++) {
			if (!test_and_set_bit(ESPF_ERROR, &esp->flags))
				esp->dev->stats.rx_errors++;
			cp++;
			printk("esp8266: Parity Errors\n");
			continue;
		}
		esp->data[index] = *(cp + index);
		index++;
	}

	ret = esp_read(esp);
	if (ret < 0)
		printk("esp8266: esp receive error\n");

	printk("Received data: ");
	print_msg(esp);
}

static void esptty_close(struct tty_struct *tty)
{
	printk("esp8266: esptty_close called\n");

	struct esp8266 *esp = (struct esp8266 *) tty->disc_data;

	tty->disc_data = NULL;
	esp->tty = NULL;
	unregister_netdev(esp->dev);
}


static struct tty_ldisc_ops esp8266_ldisc = {
	.owner		= THIS_MODULE,
	.magic		= TTY_LDISC_MAGIC,
	.name		= "esp8266",
	.open		= esptty_open,
	.close		= esptty_close,
	.receive_buf 	= esptty_receive_buf,
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
