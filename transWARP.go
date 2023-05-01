/* transWARP
 * Copyright (C) 2023 Birger Schmidt <bs-warp@netgaroo.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

package main

import (
    "context"
    "fmt"
    "log"
    "time"
    "net/http"
    "net"
    "strings"
    "strconv"
    "encoding/json"
    "bufio"
    "io"
    "io/ioutil"
    "os"

    flag "github.com/spf13/pflag"
    "github.com/cpuchip/zeroconf/v2"
)

var (
    my_http_port string = ""
    alreadyDone = make(map[string]map[string]bool)
    mac_map = make(map[string]bool)
    transall bool
    transWARP_bin string
    WARPfirmware_bin string
)

type DeviceInfo struct {
    // The Mesh-Node-Mac is not in the JSON that the EN+ charger gives us, but we just add it for convinience.
    MeshNodeMac  string
    // some fields are just ignored because of missing relevance
    ChargerSN    string `json:"charger_sn"`       // '12345678901234'
    ChargerVer   string `json:"charger_version"`  // 'V1.1.538'
    DevCode      int    `json:"charger_dev_code"` // 37
    DevName      string `json:"charger_dev_name"` // 'AC011K-AE-25'
//  GatewaySN    string `json:"gateway_sn"`       // 'ESP32GATEWAY001'
    GatewayVer   string `json:"gateway_version"`  // 'V3.2.589'
//  GroupName    string `json:"group_name"`       // '--'
//  IDFVersion   string `json:"idf_version"`      // 'v3.2-130-g8e51f7e23'
    Ip           string `json:"ip"`               // '192.168.188.58'
//  MDFVersion   string `json:"mdf_version"`      // 'v1.1'
    MeshID       string `json:"mesh_id"`          // '65684339464f'
//  MlinkTrigger int    `json:"mlink_trigger"`    // 0
//  MlinkVersion int    `json:"mlink_version"`    // 2
    Name         string `json:"name"`             // 'ENPLUS_SN12345678901234'
//  PosInfo      string `json:"pos_info"`         // ''
//  SrvLink      int    `json:"srv_link_status"`  // 0
    StatusCode   int    `json:"status_code"`      // 0
//  StatusMsg    string `json:"status_msg"`       // 'MDF_OK'
//  Tid          string `json:"tid"`              // '5'
//  Version      string `json:"version"`          // 'v1.0'
}

func DownloadFile(mac string, filepath string, url string) error {
	// Check if file already exists
	if _, err := os.Stat(filepath); err == nil {
		log.Printf("[%s] Backup (%s) already exists, skipping download\n", mac, filepath)
		return nil
	}

	// Create the file
	out, err := os.Create(filepath)
	if err != nil { return err }
	defer out.Close()

	// Download the file
    log.Printf("[%s] Download %s\n", mac, url)
	resp, err := http.Get(url)
	if err != nil { return err }
	defer resp.Body.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil { return err }

	log.Printf("[%s] Backup '%s' downloaded and saved\n", mac, filepath)
	return nil
}

func UploadFile(url string, filename string) (string, []byte) {
    client := &http.Client{}
    data, err := os.Open(filename)
    if err != nil { log.Fatal(err) }
    req, err := http.NewRequest("POST", url, data)
    if err != nil { log.Fatal(err) }
    stat, err := data.Stat()
    if err != nil { log.Fatal(err) }
    req.Header.Add("Content-Length", strconv.FormatInt(stat.Size(), 10))
    resp, err := client.Do(req)
    if err != nil { log.Fatal(err) }
    content, err := ioutil.ReadAll(resp.Body)
    if err != nil { log.Fatal(err) }
    return resp.Status, content
}

func ENplus2transWARP(ip string, port int, mac string) {

    if alreadyDone[mac]["ENplus2transWARP"] {
        return
    }
    if alreadyDone[mac] == nil { alreadyDone[mac] = make(map[string]bool) }
    alreadyDone[mac]["ENplus2transWARP"] = true

    log.Printf("[%s] Found EN+ device: %s\n", mac, ip)

    // request device_info

   	client := &http.Client{}
    url := fmt.Sprintf("http://%v:%v/device_request", ip, port)
    log.Printf("[%s] Request device-info from %s\n", mac, url)
	var data = strings.NewReader(`{"request": "get_device_info"}`)
	req, err := http.NewRequest("POST", url, data)
	if err != nil { log.Fatal(err) }
	req.Header.Set("Content-Type", "application/JSON")
	req.Header.Set("Mesh-Node-Mac", mac)
	req.Header.Set("cache-control", "no-cache")
	resp, err := client.Do(req)
	if err != nil { log.Fatal(err) }
	defer resp.Body.Close()
    var device_info DeviceInfo
    err = json.NewDecoder(resp.Body).Decode(&device_info)
	if err != nil { log.Fatal(err) }
    device_info.ChargerSN = device_info.ChargerSN[2:]
    device_info.MeshNodeMac = mac
    log.Printf("[%s] Device info: %+v\n", mac, device_info)

    conn, err := net.Dial("tcp", ip + ":80")
    if err != nil { log.Fatal(err) }
    defer conn.Close()
    my_ip := conn.LocalAddr().(*net.TCPAddr).IP.String()
    //log.Printf("[%s] Local IP address:", mac, my_ip)

    if (transall || mac_map[mac]) { 
        go func() { start_httpd(my_ip) }()
        for my_http_port == "" { time.Sleep(1 * time.Second) }
    }

	// Check if device info file already exists
    json_filepath := "AC011K_" + mac + "_device_info.json"
    // MeshNodeMac:1c9dc25743f8 ChargerSN:10052109254216 ChargerVer:V1.2.460 DevCode:37 DevName:AC011K-AE-25 GatewayVer:V3.2.589 Ip:192.168.188.179 MeshID:54573238353e Name:ENPLUS_SN10052109254216
	if _, err := os.Stat(json_filepath); err == nil {
		log.Printf("[%s] Device info JSON file (%s) already exists, skip saving\n", mac, json_filepath)
    } else {
        // Write device info data to file
        file, err := json.MarshalIndent(device_info, "", "  ")
        if err != nil {
            log.Fatalf("[%s] %s\n", mac, err)
        }
        err = ioutil.WriteFile(json_filepath, file, 0644)
        if err != nil {
            log.Fatalf("[%s] %s\n", mac, err)
        }
        log.Printf("[%s] Saved device info JSON file (%s) successfully\n", mac, json_filepath)
    }

    if !(transall || mac_map[mac]) { 
        return
    }

    // trigger OTA transWARP.bin flash

    url = fmt.Sprintf("http://%v:%v/ota/url", ip, port)
    firmware_url := "http://" + my_ip + ":" + my_http_port + "/" + my_ip + "/" + transWARP_bin
    log.Printf("[%s] Triggering the intermediate [%s] firmware update on the EN+ device [%s]\n", mac, firmware_url, url)
    data = strings.NewReader(`{"request": "mlink_ota_firmware"}`)
    req, err = http.NewRequest("POST", url, data)
    if err != nil { log.Fatal(err) }
    req.Header.Set("Content-Type", "application/JSON")
    req.Header.Set("Mesh-Node-Mac", mac)
    req.Header.Set("cache-control", "no-cache")
    req.Header.Set("Firmware-Name", "warp-more-hardware")
    req.Header.Set("Firmware-Url", firmware_url)
    resp, err = client.Do(req)
    if err != nil { log.Fatal(err) }
    defer resp.Body.Close()
    err = json.NewDecoder(resp.Body).Decode(&device_info)
    if err != nil { log.Fatal(err) }
    //{'status_code': 0, 'status_msg': 'MDF_OK'}
    if device_info.StatusCode == 0 {
        log.Printf("[%s] EN+ -> transWARP transition successfully initiated. The box is now preparing itself for the next step and rebooting. (this usually takes about 30 seconds)\n", mac)
    } else {
        log.Printf("[%s] Got OTA update (EN+ -> transWARP) error code: %d", mac, device_info.StatusCode)
        alreadyDone[mac]["ENplus2transWARP"] = false
    }
}

func TransWARP2WARP(ip string, port int, info_text []string) {

    // get info from mdns text
    info := make(map[string]string)
    for _, s := range info_text {
        parts := strings.SplitN(s, "=", 2)
        info[parts[0]] = parts[1]
    }

    if !alreadyDone[info["mac"]]["TransWARP2WARP_" + ip] {
        if alreadyDone[info["mac"]] == nil { alreadyDone[info["mac"]] = make(map[string]bool) }
        alreadyDone[info["mac"]]["TransWARP2WARP_" + ip] = true

        log.Printf("[%s] Found transWARP device: %s %s\n",info["mac"], ip, info_text)
    }

    if !(transall || mac_map[info["mac"]]) { 
        return
    }

	// Read device info from file
    json_filepath := "AC011K_" + info["mac"] + "_device_info.json"
    file, err := ioutil.ReadFile(json_filepath)
    if err != nil {
        log.Printf("[%s] unable to get device info (%s) (%s)\n", info["mac"], json_filepath, err)
    }
    var device_info DeviceInfo
    _ = json.Unmarshal([]byte(file), &device_info)

    if !alreadyDone[info["mac"]]["TransWARP2WARP_BACKUP"] {
        if len(info["BACKUP"]) > 0 {
            if alreadyDone[info["mac"]] == nil { alreadyDone[info["mac"]] = make(map[string]bool) }
            alreadyDone[info["mac"]]["TransWARP2WARP_BACKUP"] = true

            url := fmt.Sprintf("http://%v:%v%s", ip, port, info["BACKUP"])
            backupFileName := "AC011K_" + info["mac"] + "_" + device_info.Name + "_" + device_info.GatewayVer + "_" + device_info.ChargerVer + "_firmware_backup.bin"

            err := DownloadFile(info["mac"], backupFileName, url)
            if err != nil {
                log.Fatalf("[%s] %s\n", info["mac"], err)
            }
        }
    }

    conn, err := net.Dial("tcp", ip + ":80")
    if err != nil {
        log.Printf("[%s] %s\n", info["mac"], err)
        return
    }
    defer conn.Close()
    my_ip := conn.LocalAddr().(*net.TCPAddr).IP.String()

    go func() { start_httpd(my_ip) }()
    for my_http_port == "" { time.Sleep(1 * time.Second) }

    firmware_url := "http://" + my_ip + ":" + my_http_port + "/" + my_ip + "/" + WARPfirmware_bin

    if !alreadyDone[info["mac"]]["TransWARP2WARP_GET"] {
        if len(info["GET"]) > 0 {
            if alreadyDone[info["mac"]] == nil { alreadyDone[info["mac"]] = make(map[string]bool) }
            alreadyDone[info["mac"]]["TransWARP2WARP_GET"] = true

            url := fmt.Sprintf("http://%v:%v%s", ip, port, info["GET"])
            log.Printf("[%s] Triggering the WARP [%s] firmware update on the transWARP device [%s]\n", info["mac"], firmware_url, url)
            client := &http.Client{}
            req, err := http.NewRequest("GET", url, nil)
            if err != nil { log.Fatal(err) }
            req.Header.Set("Firmware-Name", "warp-more-hardware")
            req.Header.Set("Firmware-Url", firmware_url)
            resp, err := client.Do(req)
            if err != nil {
                log.Printf("[%s] %s\n", info["mac"], err)
                alreadyDone[info["mac"]]["TransWARP2WARP_GET"] = false
                return
            } else {
                defer resp.Body.Close()
                scanner := bufio.NewScanner(resp.Body)
                for scanner.Scan() {
                    chunk := scanner.Bytes()
                    // process the chunk here
                    log.Printf("[%s] %s\n", info["mac"], string(chunk))
                }
                if err := scanner.Err(); err != nil {
                    log.Printf("[%s] %s\n", info["mac"], err)
                    alreadyDone[info["mac"]]["TransWARP2WARP_GET"] = false
                    return
                }
                log.Printf("[%s] transWARP -> WARP transition done.\n\nConnect to the new WiFi named AC011K-%s, then configure your WARP box at http://10.0.0.1/ and enjoy!\n\n", info["mac"], device_info.ChargerSN)
            }
            //TODO trigger twice if we need to move transWARP out of the way?
            //alreadyDone[info["mac"]]["TransWARP2WARP_GET"] = false
        }
    }

    if false && !alreadyDone[info["mac"]]["TransWARP2WARP_POST"] {
        if len(info["POST"]) > 0 {
            if alreadyDone[info["mac"]] == nil { alreadyDone[info["mac"]] = make(map[string]bool) }
            alreadyDone[info["mac"]]["TransWARP2WARP_POST"] = true

            // trigger OTA WARP firmware flash

            client := &http.Client{}
            //url := fmt.Sprintf("http://%v:%v/ota/url", ip, port)
            url := fmt.Sprintf("http://%v:%v/AC011K_flash_WARP_firmware.bin.post", ip, port)
            log.Printf("Triggering the WARP [%s] firmware update on the transWARP device [%s]\n", firmware_url, url)
            data := strings.NewReader(firmware_url)
            req, err := http.NewRequest("POST", url, data)
            if err != nil { log.Fatal(err) }
            req.Header.Set("Content-Type", "application/JSON")
            req.Header.Set("cache-control", "no-cache")
            req.Header.Set("Firmware-Name", "warp-more-hardware")
            req.Header.Set("Firmware-Url", firmware_url)
            resp, err := client.Do(req)
            if err != nil {
                log.Println(err)
                alreadyDone[info["mac"]]["TransWARP2WARP_POST"] = false
            } else {
                bodyText, err := io.ReadAll(resp.Body)
                if err != nil { log.Println(err) }
                log.Printf("OTA update answer (transWARP -> WARP): %s\n", bodyText)
                resp.Body.Close()
            }

            // log.Println("Upload the WARP firmware")
            // url := fmt.Sprintf("http://%v:%v%s", ip, port, info["POST"])

            // status, content := UploadFile(url, "build/warpAC011K_firmware_2_0_12_64033399_merged.bin")
            // log.Println("Status:", status)
            // log.Printf("%s\n", string(content))
        }
        log.Println("OTA update finish...")
    }

    return;

     // print ("Persist state to", transWARP_json)
     // # write the state to a file
     // with open(transWARP_json, 'w') as f:
     //     json.dump(device_info, f)

}

func spinner() {
    chars := []rune{'|', '/', '-', '\\'}
    i := 0
    for {
        fmt.Printf("\r%c\r", chars[i])
        i = (i + 1) % len(chars)
        time.Sleep(300 * time.Millisecond)
    }
}

func loggingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[WARNING, this is critical, do not interrupt!] Serving %s %s %s", r.RemoteAddr, r.Method, r.URL)
		h.ServeHTTP(w, r)
	})
}

func start_httpd(ip string) {
    if alreadyDone[ip]["HTTPD"] {
        return
    }
    if alreadyDone[ip] == nil { alreadyDone[ip] = make(map[string]bool) }
    alreadyDone[ip]["HTTPD"] = true

    // serve the current working dir
    cwd, err := os.Getwd()
    if err != nil {
        log.Println(err)
    }

	http.Handle("/" + ip + "/", loggingHandler(http.StripPrefix("/" + ip + "/", http.FileServer(http.Dir(cwd)))))

	// Listen on a random port on the given ip
	listener, err := net.Listen("tcp", ip + ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

    // save the port number as string in my_http_port
    my_http_port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

    log.Printf("[http://%s:%s/%s/] Start HTTP server to serve '%s/'\n", ip, my_http_port, ip, cwd)

	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
    var help bool
    var boxes string
    var macs []string

    flag.StringSliceVar(&macs, "mac", []string{}, "MAC address of EN+ device to transform (can be given multiple times)")
    flag.StringVar(&transWARP_bin, "intermediate", "transWARP.bin", "file name of the intermediate firmware (usually comes packaged with this program)")
    flag.StringVar(&WARPfirmware_bin, "warp", "warpAC011K_firmware_2_0_12_64033399_merged.bin", "file name of the WARP firmware (v2.0.12 is known to work)")
    flag.BoolVar(&transall, "transall", false, "transform ALL found EN+ devices to WARP more hardware firmware without further questioning")
    flag.BoolVar(&help, "help", false, "Print this help")

    flag.Parse()

    fmt.Println("This is transWARP, your way to upgrade your EN+ wallbox from the vendor firmware to the WARP more hardware firmware.\n")
    if help {
        flag.PrintDefaults()
        os.Exit(0)
    }

    for _, mac := range macs {
        mac_map[mac] = true
    }

    if transall {
        boxes = "ALL EN+ devices"
    } else if len(macs) > 0 {
        boxes = fmt.Sprintf("the EN+ device(s) with the following MAC address(es): %v ", macs)
    } else {
        boxes = "the EN+ device(s) in the LAN"
    }

    fmt.Println(
        "I'll try to do the following steps:\n",
        "   * find " + boxes + "\n",
        "   * get the device info\n",
    )

    if transall || len(macs) > 0 { 
        cwd, err := os.Getwd()
        if err != nil {
            log.Fatalln(err)
        }

        file, err := os.OpenFile(transWARP_bin, os.O_RDONLY, 0666)
        if err != nil { log.Fatalf("Unable to read from %s/%s (%s)\n", cwd, transWARP_bin, err) }
        file.Close()

        file, err = os.OpenFile(WARPfirmware_bin, os.O_RDONLY, 0666)
        if err != nil { log.Fatalf("Unable to read from %s/%s (%s)\n", cwd, WARPfirmware_bin, err) }
        file.Close()

        fmt.Println(
            "    * flash the transWARP intermediate firmware\n",
            "   * download a backup of the old firmware\n",
            "   * flash the new WARP more hardware firmware\n",
            "then you should be able to connect to a new WiFi named something like AC011K-1234567890\n",
        )
    } else {
        fmt.Println("You need to call me with a parameter to do more.\n")
    }

    go func() { spinner() }()

    for {

        // use mdns service discovery to find the EN+ wallboxes to transWARP

        // Channel to receive discovered service entries
        entries := make(chan *zeroconf.ServiceEntry)

        go func(results <-chan *zeroconf.ServiceEntry) {
            for entry := range results {
                if strings.HasPrefix(entry.Instance, "Mesh") {
                    //log.Printf("Found EN+ device: %s %s\n", entry.AddrIPv4[0].String(), entry.Text)
                    if len(entry.Text) != 1 {
                        //log.Println("Error: Mesh-Node-Mac is missing in _EN-http._tcp mdns entry")
                        continue;
                    }
                    ENplus2transWARP(entry.AddrIPv4[0].String(), entry.Port, entry.Text[0][4:])
                    continue;
                }
                if strings.HasPrefix(entry.Instance, "transWARP") && (len(entry.Text) > 0) {
                    //log.Printf("Found transWARP device: %s %s\n", entry.AddrIPv4[0].String(), entry.Text)
                    TransWARP2WARP(entry.AddrIPv4[0].String(), entry.Port, entry.Text)
                    continue;
                }
                //log.Printf("Ignoring unknown EN+ device. %#v\n", entry)
            }
        }(entries)

        ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(10)) // 10 second timeout
        defer cancel()
        // Discover _EN-http._tcp services on the network
        err := zeroconf.Browse(ctx, "_EN-http._tcp", "local.", entries)
        if err != nil {
            log.Fatalln("Failed to browse:", err.Error())
        }

        <-ctx.Done()

    }

	// Wait some additional time to see debug messages on go routine shutdown.
	time.Sleep(1 * time.Second)
}

