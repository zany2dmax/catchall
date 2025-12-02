package qualysclient

type QualysSearchResponse struct {
    ResponseMessage string `json:"responseMessage"`
    ResponseCode    string `json:"responseCode"`
    Count           int    `json:"count"`
    LastSeenAssetID int64  `json:"lastSeenAssetId"`
    HasMore         int    `json:"hasMore"`
    AssetListData   struct {
        Assets []Asset `json:"asset"`
    } `json:"assetListData"`
}

type Asset struct {
    AssetID  int64  `json:"assetId"`
    Address  string `json:"address"`
    HostName string `json:"assetName"`

    NetworkInterfaceListData struct {
        Interfaces []NetworkInterface `json:"networkInterface"`
    } `json:"networkInterfaceListData"`

    OpenPortListData struct {
        OpenPorts []OpenPort `json:"openPort"`
    } `json:"openPortListData"`
}

type NetworkInterface struct {
    Hostname    string  `json:"hostname"`
    AddressIPv4 string  `json:"addressIpV4"`
    AddressIPv6 *string `json:"addressIpV6"`
    MacAddress  string  `json:"macAddress"`
}

type OpenPort struct {
    Port            int     `json:"port"`
    Description     string  `json:"description"`
    Protocol        string  `json:"protocol"`
    DetectedService *string `json:"detectedService"`
    FirstFound      string  `json:"firstFound"`
    LastUpdated     string  `json:"lastUpdated"`
}

type FilterRequest struct {
    Filters   []FilterCriteria `json:"filters"`
    Operation string           `json:"operation,omitempty"`
}

type FilterCriteria struct {
    Field    string      `json:"field"`
    Operator string      `json:"operator"`
    Value    interface{} `json:"value"`
}
