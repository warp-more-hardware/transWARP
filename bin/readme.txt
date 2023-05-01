This is transWARP
~~~~~~~~~~~~~~~~~

Dies ist transWARP, ein kleines Programm um die EN+ original
Firmware durch die WARP-more-hardware Firmware zu ersetzen
ohne die Wallbox anfassen und aufschrauben zu müssen.

This is the little helper to get your EN+ wallbox upgraded
to the WARP-more-hardware firmware without having to touch
your hardware and screwing around.

Die original Handy App (Chargin) geht hinterher nicht mehr!
Und es ist auf jeden Fall sinnvoll sich vorher
* alle Daten zu speichern die man aus der Chargin App
  noch haben möchte sowie
* alle RFID Karten aus der App zu löschen.

The original smartphone app wil not work anymore after the
transition!
It is highly recommeded to do the following before upgrading:
* save all data you may want to keep from the chargin app and
* remove all RFID cards from the app

Die Voraussetzung zum Erfolg ist, dass ihr transWARP im
selben WiFi aufruft in dem auch eure Wallbox ist.

The route to success is to call transWARP while conected
to the same WiFi network as the EN+ wallbox is in.

Einfach das Programm aufrufen welches für dein Betriebssystem
passt und alles wird gut.

Just call the binary that fits your platform and follow
the instructions.

Die Quellen finden sich unter:
Find the sources at:
https://github.com/warp-more-hardware/transWARP

This is how it looks on my mac:


    ➜ ./transWARP-amd64-darwin

    This is transWARP, your way to upgrade your EN+ wallbox from the vendor firmware to the WARP more hardware firmware.

    I'll try to do the following steps:
        * find the EN+ device(s) in the LAN
        * get the device info

    You need to call me with a parameter to do more.

    2023/04/11 17:54:44 [1c9dc25743f8] Found EN+ device: 192.168.188.179
    2023/04/11 17:54:44 [1c9dc25743f8] Request device-info from http://192.168.188.179:80/device_request
    2023/04/11 17:54:44 [1c9dc25743f8] Device info: {MeshNodeMac:1c9dc25743f8 ChargerSN:12345678901234 ChargerVer:V1.2.460 DevCode:37 DevName:AC011K-AE-25 GatewayVer:V3.2.589 Ip:192.168.188.179 MeshID:54573238353e Name:ENPLUS_SN12345678901234 StatusCode:0}
    2023/04/11 17:54:44 [1c9dc25743f8] Saved device info JSON file (AC011K_1c9dc25743f8_device_info.json) successfully
    ^C


    ➜  ./transWARP-amd64-darwin --help

    This is transWARP, your way to upgrade your EN+ wallbox from the vendor firmware to the WARP more hardware firmware.

          --help                  Print this help
          --intermediate string   file name of the intermediate firmware (usually comes packaged with this program) (default "transWARP.bin")
          --mac strings           MAC address of EN+ device to transform (can be given multiple times)
          --transall              transform ALL found EN+ devices to WARP more hardware firmware without further questioning
          --warp string           file name of the WARP firmware (v2.0.12 is known to work) (default "warpAC011K_firmware_2_0_12_64033399_merged.bin")


    ➜ ./transWARP-amd64-darwin --transall

    This is transWARP, your way to upgrade your EN+ wallbox from the vendor firmware to the WARP more hardware firmware.

    I'll try to do the following steps:
        * find ALL EN+ devices
        * get the device info

        * flash the transWARP intermediate firmware
        * download a backup of the old firmware
        * flash the new WARP more hardware firmware
     then you should be able to connect to a new WiFi named something like AC011K-1234567890

    2023/04/11 17:58:28 [1c9dc25743f8] Found EN+ device: 192.168.188.179
    2023/04/11 17:58:28 [1c9dc25743f8] Request device-info from http://192.168.188.179:80/device_request
    2023/04/11 17:58:28 [1c9dc25743f8] Device info: {MeshNodeMac:1c9dc25743f8 ChargerSN:12345678901234 ChargerVer:V1.2.460 DevCode:37 DevName:AC011K-AE-25 GatewayVer:V3.2.589 Ip:192.168.188.179 MeshID:54573238353e Name:ENPLUS_SN12345678901234 StatusCode:0}
    2023/04/11 17:58:28 [http://192.168.188.79:62737/192.168.188.79/] Start HTTP server to serve '/space/develop/git/warp-more-hardware-transWARP/'
    2023/04/11 17:58:29 [1c9dc25743f8] Device info JSON file (AC011K_1c9dc25743f8_device_info.json) already exists, skip saving
    2023/04/11 17:58:29 [1c9dc25743f8] Triggering the intermediate [http://192.168.188.79:62737/192.168.188.79/build/transWARP.bin] firmware update on the EN+ device [http://192.168.188.179:80/ota/url]
    2023/04/11 17:58:29 [WARNING, this is critical, do not interrupt!] Serving 192.168.188.179:60041 GET /192.168.188.79/build/transWARP.bin
    2023/04/11 17:58:48 [1c9dc25743f8] EN+ -> transWARP transition successfully initiated. The box is now preparing itself for the next step and rebooting. (this usually takes about 30 seconds)
    2023/04/11 17:59:08 [1c9dc25743f8] Found transWARP device: 192.168.188.179 [GET=/AC011K_flash_WARP_firmware.bin BACKUP=/AC011K_ENplus_flash_backup.bin mac=1c9dc25743f8 transWARP=AC011K]
    2023/04/11 17:59:08 [1c9dc25743f8] Backup (AC011K_1c9dc25743f8_ENPLUS_SN12345678901234_V3.2.589_V1.2.460_firmware_backup.bin) already exists, skipping download
    2023/04/11 17:59:08 [1c9dc25743f8] Triggering the WARP [http://192.168.188.79:62737/192.168.188.79/build/warpAC011K_firmware_2_0_12_642fb99d_ecf213009b8ad57_merged.bin] firmware update on the transWARP device [http://192.168.188.179:80/AC011K_flash_WARP_firmware.bin]
    2023/04/11 17:59:11 [1c9dc25743f8] You triggered the firmware upgrade successfully.
    2023/04/11 17:59:11 [WARNING, this is critical, do not interrupt!] Serving 192.168.188.179:49315 GET /192.168.188.79/build/warpAC011K_firmware_2_0_12_642fb99d_ecf213009b8ad57_merged.bin
    2023/04/11 17:59:20 [1c9dc25743f8] firmware flash success 10%
    2023/04/11 17:59:22 [1c9dc25743f8] firmware flash success 20%
    2023/04/11 17:59:25 [1c9dc25743f8] firmware flash success 30%
    2023/04/11 17:59:27 [1c9dc25743f8] firmware flash success 40%
    2023/04/11 17:59:30 [1c9dc25743f8] firmware flash success 50%
    2023/04/11 17:59:33 [1c9dc25743f8] firmware flash success 60%
    2023/04/11 17:59:35 [1c9dc25743f8] firmware flash success 70%
    2023/04/11 17:59:38 [1c9dc25743f8] firmware flash success 80%
    2023/04/11 17:59:43 [1c9dc25743f8] firmware flash success 90%
    2023/04/11 17:59:46 [1c9dc25743f8] File reception / flashing complete, restarting into the new firmware.
    2023/04/11 17:59:46 [1c9dc25743f8] transWARP -> WARP transition done.

    Connect to the new WiFi named AC011K-12345678901234, then configure your WARP box at http://10.0.0.1/ and enjoy!

    ^Csignal: interrupt

