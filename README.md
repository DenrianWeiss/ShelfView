# ShelfView

ShelfView is a unified BMC control platform that let you control all your servers in a single application.  

This open source repo contains source code of the core library itself (libbcontrol) and the cross platform shell on Avalonia, apple/android/harmonyos ui does not included.

[Download](https://catball.argus.feralhosting.com/shelfview/) the release at our website, or join the [Telegram Group](https://t.me/+Xz5RML_rurQyM2Fl) or [Lark Group](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=0c9s12fd-47fb-4138-856b-909616263a15) to have some feedback.

## Platform support

Power Control, Serial over LAN and FRU info is transmitted over standard RMCP+/RedFish protocol, and should work with every server that is not cursed enough.  

Unfortunately, KVM does not have standarized wire protocol, so its support can only be done as platform-to-platform port, we currently support:

- Part of the MegaRAC derived family
- iDRAC 7/8
- iLO 5
- Part of Oracle iLOM
- Part of Huawei iBMC
- Part of ATEN Supermicro BMC
- OpenBMC/OurBMC

If you find your platform not supported, please contact us to discuss how to adapt it.

## License

The controller lib and avalonia UI is licensed under AGPL-or-business-contract.
