package drda

import (
	"time"
	"fmt"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/protos/tcp"
	"github.com/elastic/beats/packetbeat/publish"
	"github.com/Intermernet/ebcdic"
)

/*

Parse DRDA Protocol used by IBM DB2 or Apache Derby (and possibly other databases)

Limitations:
- Raw message not supported (guess that makes not much sense here)
- No tests yet

Dependencies:
- https://github.com/Intermernet/ebcdic

Sample Output

{
    "@timestamp":"2016-02-29T20:07:39.074Z",
    "beat":{
        "hostname":"Hendriks-MacBook-Pro.local",
        "name":"Hendriks-MacBook-Pro.local"
    },
    "bytes_in":217,
    "bytes_out":100,
    "client_ip":"127.0.0.1",
    "client_port":52933,
    "client_proc":"",
    "client_server":"Hendriks-MacBook-Pro.local",
    "count":1,
    "ip":"127.0.0.1",
    "port":1527,
    "proc":"",
    "reponses":{
        "ACCRDBRM":{
            "codepoint":8705,
            "correlation_id":2,
            "description":"Access to RDB Completed",
            "format":82,
            "length":57,
            "length2":51,
            "parameters":{
                "PRDID":{
                    "codepoint":4398,
                    "data_ascii":"CSS10120",
                    "data_ebcdic":"\ufffd\ufffd두\ufffd\u0016\ufffd",
                    "desc":"Product-Specific Identifier",
                    "length":12
                },
                "SVRCOD":{
                    "codepoint":4425,
                    "data_ascii":"\u0000\u0000",
                    "data_ebcdic":"\u0000\u0000",
                    "desc":"Severity Code",
                    "length":6
                },
                "TYPDEFNAM":{
                    "codepoint":47,
                    "data_ascii":"QTDSQLASC",
                    "data_ebcdic":"\ufffd\ufffd\ufffd\ufffd\ufffd\u003c\ufffd\ufffd\ufffd",
                    "desc":"Data Type Definition Name",
                    "length":13
                },
                "TYPDEFOVR":{
                    "codepoint":53,
                    "data_ascii":"\u0000\u0006\u0011\ufffd\u0004\ufffd\u0000\u0006\u0011\ufffd\u0004\ufffd",
                    "data_ebcdic":"\u0000\ufffd\u0011朽\u0000\ufffd\u0011Ɯ\ufffd",
                    "desc":"TYPDEF Overrides",
                    "length":16
                }
            }
        },
        "SECCHKRM":{
            "codepoint":4633,
            "correlation_id":1,
            "description":"Security Check",
            "format":66,
            "length":21,
            "length2":15,
            "parameters":{
                "SECCHKCD":{
                    "codepoint":4516,
                    "data_ascii":"\u0000",
                    "data_ebcdic":"\u0000",
                    "desc":"Security Check Code",
                    "length":5
                },
                "SVRCOD":{
                    "codepoint":4425,
                    "data_ascii":"\u0000\u0000",
                    "data_ebcdic":"\u0000\u0000",
                    "desc":"Severity Code",
                    "length":6
                }
            }
        },
        "unknown_49152":{
            "codepoint":49152,
            "correlation_id":2,
            "description":"",
            "format":2,
            "length":22,
            "length2":16,
            "parameters":{
                "unknown_49153":{
                    "codepoint":49153,
                    "data_ascii":"\u0002",
                    "data_ebcdic":"\u0002",
                    "desc":"",
                    "length":5
                },
                "unknown_49154":{
                    "codepoint":49154,
                    "data_ascii":"APP",
                    "data_ebcdic":"\ufffd\u0026\u0026",
                    "desc":"",
                    "length":7
                }
            }
        }
    },
    "requests":{
        "ACCRDB":{
            "codepoint":8193,
            "correlation_id":2,
            "description":"Access RDB",
            "direction":1,
            "format":1,
            "length":170,
            "length2":164,
            "parameters":{
                "CRRTKN":{
                    "codepoint":8501,
                    "data_ascii":"\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd.\ufffd\ufffd\ufffd\ufffd\u0001S.\ufffd\ufffdB",
                    "data_ebcdic":"NF000001\u0006CEC5\u0001\ufffd\u0006u\ufffd\ufffd",
                    "desc":"Correlation Token",
                    "length":23
                },
                "PRDDTA":{
                    "codepoint":8452,
                    "data_ascii":"7\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd@@@@@@@@@@@@@@@\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd@@@@@@@@@@@@@@@@\u0000",
                    "data_ebcdic":"\u0004DNC10120JVM               derbydncmain                \u0000",
                    "desc":"Product-Specific Data",
                    "length":60
                },
                "PRDID":{
                    "codepoint":4398,
                    "data_ascii":"DNC10120",
                    "data_ebcdic":"\ufffd+䑐\ufffd\u0016\ufffd",
                    "desc":"Product-Specific Identifier",
                    "length":12
                },
                "RDBACCCL":{
                    "codepoint":8463,
                    "data_ascii":"$\u0007",
                    "data_ebcdic":"\ufffd",
                    "desc":"RDB Access Manager Class",
                    "length":6
                },
                "RDBNAM":{
                    "codepoint":8464,
                    "data_ascii":"MyDbTest;create=true",
                    "data_ebcdic":"(`\ufffd\ufffd\ufffd\ufffd\ufffdț\ufffd\ufffd\ufffd/\ufffd\ufffd\u0015\ufffd\ufffd\ufffd\ufffd",
                    "desc":"Relational Database Name",
                    "length":24
                },
                "TYPDEFNAM":{
                    "codepoint":47,
                    "data_ascii":"QTDSQLASC",
                    "data_ebcdic":"\ufffd\ufffd\ufffd\ufffd\ufffd\u003c\ufffd\ufffd\ufffd",
                    "desc":"Data Type Definition Name",
                    "length":13
                },
                "TYPDEFOVR":{
                    "codepoint":53,
                    "data_ascii":"\u0000\u0006\u0011\ufffd\u0004\ufffd\u0000\u0006\u0011\ufffd\u0004\ufffd\u0000\u0006\u0011\ufffd\u0004\ufffd",
                    "data_ebcdic":"\u0000\ufffd\u0011朽\u0000\ufffd\u0011\ufffd\ufffd^\u0000\ufffd\u0011Ɯ\ufffd",
                    "desc":"TYPDEF Overrides",
                    "length":22
                }
            }
        },
        "SECCHK":{
            "codepoint":4206,
            "correlation_id":1,
            "description":"Security Check",
            "direction":1,
            "format":65,
            "length":47,
            "length2":41,
            "parameters":{
                "RDBNAM":{
                    "codepoint":8464,
                    "data_ascii":"MyDbTest;create=true",
                    "data_ebcdic":"(`\ufffd\ufffd\ufffd\ufffd\ufffdț\ufffd\ufffd\ufffd/\ufffd\ufffd\u0015\ufffd\ufffd\ufffd\ufffd",
                    "desc":"Relational Database Name",
                    "length":24
                },
                "SECMEC":{
                    "codepoint":4514,
                    "data_ascii":"\u0000\u0004",
                    "data_ebcdic":"\u0000\ufffd",
                    "desc":"Security Mechanism",
                    "length":6
                },
                "USRID":{
                    "codepoint":4512,
                    "data_ascii":"APP",
                    "data_ebcdic":"\ufffd\u0026\u0026",
                    "desc":"User ID at the Target System",
                    "length":7
                }
            }
        }
    },
    "responsetime":1,
    "server":"Hendriks-MacBook-Pro.local",
    "status":"OK",
    "type":"drda"
}


*/



type parseState int

const (
	drdaStateStart parseState = iota
	drdaStateContent
)

var stateStrings []string = []string{
	"Start",
	"Content",
}

func drdaAbbrev(codepoint uint16) string{
	abbrev := drda_abbrev[codepoint]

	if abbrev == "" {
		return fmt.Sprint("unknown_",codepoint)
	}

	return abbrev
}

func (state parseState) String() string {
	return stateStrings[state]
}

func (drda *Drda) getTransaction(k common.HashableTcpTuple) *DrdaTransaction {
	v := drda.transactions.Get(k)
	if v != nil {
		return v.(*DrdaTransaction)
	}
	return nil
}

func (drda *Drda) InitDefaults() {
	drda.maxRowLength = 1024
	drda.maxStoreRows = 10
	drda.Send_request = false
	drda.Send_response = false
	drda.transactionTimeout = protos.DefaultTransactionExpiration
}

func (drda *Drda) setFromConfig(config config.Drda) error {

	drda.Ports = config.Ports

	if config.Max_row_length != nil {
		drda.maxRowLength = *config.Max_row_length
	}
	if config.Max_rows != nil {
		drda.maxStoreRows = *config.Max_rows
	}
	if config.SendRequest != nil {
		drda.Send_request = *config.SendRequest
	}
	if config.SendResponse != nil {
		drda.Send_response = *config.SendResponse
	}
	if config.TransactionTimeout != nil && *config.TransactionTimeout > 0 {
		drda.transactionTimeout = time.Duration(*config.TransactionTimeout) * time.Second
	}
	return nil
}

func (drda *Drda) GetPorts() []int {
	return drda.Ports
}

func (drda *Drda) Init(test_mode bool, results publish.Transactions) error {

	drda.InitDefaults()
	if !test_mode {
		err := drda.setFromConfig(config.ConfigSingleton.Protocols.Drda)
		if err != nil {
			return err
		}
	}

	drda.transactions = common.NewCache(
		drda.transactionTimeout,
		protos.DefaultTransactionHashSize)
	drda.transactions.StartJanitor(drda.transactionTimeout)
	drda.results = results

	return nil
}

func (stream *DrdaStream) PrepareForNewMessage() {
	stream.data = stream.data[stream.parseOffset:]
	stream.parseState = drdaStateStart
	stream.parseOffset = 0
	stream.message = nil
}

//main loop
//return: ok, complete
func drdaMessageParser(s *DrdaStream) (bool, bool) {

	m := s.message
	m.parameters = make(map[uint16]Parameter)
	for s.parseOffset < len(s.data) {

		direction := ""

		if m.Direction==0 {
			direction = "Response"
		} else {
			direction = "Request"
		}

		logp.Debug("drdadetailed", "Direction %s",direction)
		logp.Debug("drdadetailed", "parser round with parseState = %s and offset: %d, len of data is %d", s.parseState, s.parseOffset, len(s.data))

		switch s.parseState {
		case drdaStateStart:

			m.start = s.parseOffset
			if len(s.data[s.parseOffset:]) < 10 {
				logp.Err("DRDA DDM Message too short. Ignore it.")
				return false, false
			}

			hdr := s.data[s.parseOffset : s.parseOffset+10]
			if hdr[2] != DRDA_MAGIC {
				logp.Err("No DRDA magic byte found (%X) but %X", DRDA_MAGIC, uint8(hdr[2]))
				return false, false
			}

			if m.ddm.Length != 0 {
				logp.Err("DDM already initialized.")
			}

			if m.RemainingLength != 0 {
				logp.Err("Remaining length must be 0.")
			}

			ddm := &Ddm{}

			ddm.Length= uint16(hdr[0])<<8 | uint16(hdr[1])
			ddm.Format = uint8(hdr[3])
			ddm.Cor = uint16(hdr[4])<<8 | uint16(hdr[5])
			ddm.Length2 = uint16(hdr[6])<<8 | uint16(hdr[7])
			ddm.Codepoint = uint16(hdr[8])<<8 | uint16(hdr[9])
			m.ddm = *ddm

			m.end = int(ddm.Length)
			m.RemainingLength = int(ddm.Length) - 10;

			logp.Debug("drdadetailed", ">>>> DRDA DDM: Length %d, codepoint %s",ddm.Length, drdaAbbrev(ddm.Codepoint))
		    s.parseOffset += 10

			if ddm.Length > 10 {
				s.parseState = drdaStateContent
				continue
			} else {
				logp.Debug("drdadetailed", "       - No parameters")
				return true, true
			}
		break

		case drdaStateContent:

		    if len(s.data[s.parseOffset:]) < 4 {
				logp.Err("Parameters message too short. Ignore it.")
				return false, false
			}

		    contentLength :=  uint16(s.data[s.parseOffset])<<8 | uint16(s.data[s.parseOffset+1])

		    if contentLength == 0 {
		    	logp.Debug("drdadetailed", "       - Parameter with zero length, thats ok but immediately advance to next DDM")
		    	s.parseOffset += m.RemainingLength
				s.parseState = drdaStateStart
				return true, true
		    }

		    if contentLength == 255 {
		    	logp.Debug("drdadetailed","        - Parameter with invalid length of 255, thats ok but immediately advance to next DDM")
		    	s.parseOffset += m.RemainingLength
		    	s.parseState = drdaStateStart
				return true, true
		    }


		    if int(contentLength) > m.RemainingLength {
		    	logp.Debug("drdadetailed","        - Parameter with invalid length of %d, thats ok but immediately advance to next DDM",int(contentLength))
		    	s.parseOffset += m.RemainingLength
		    	s.parseState = drdaStateStart
				return true, true
		    }

		    dataLength := int(contentLength) -4
		    codePoint :=  uint16(s.data[s.parseOffset+2])<<8 | uint16(s.data[s.parseOffset+3])

			parameter := &Parameter{}
			parameter.Length = contentLength
			parameter.Codepoint = codePoint

            logp.Debug("drdadetailed", "       - Parameter: Length %d %s (%s)", contentLength, drdaAbbrev(codePoint), drda_description[codePoint])
            var data []byte

			if dataLength > 0 {

			    data = s.data[s.parseOffset +4: s.parseOffset+4+dataLength]
			    parameter.ASCIIData = string(data)
			    parameter.EBCDICData = string(ebcdic.Decode(data))
			}

			m.parameters[ codePoint] = *parameter
			m.RemainingLength -= int(contentLength);
			s.parseOffset += int(contentLength);

			if m.RemainingLength <= 0 {
				s.parseState = drdaStateStart
				return true, true
			}

			break

	  } //end switch
	}//end for

	return true, false
}

type drdaPrivateData struct {
	Data [2]*DrdaStream
}

func (drda *Drda) ConnectionTimeout() time.Duration {
	return drda.transactionTimeout
}

//entry point
func (drda *Drda) Parse(pkt *protos.Packet, tcptuple *common.TcpTuple,
	dir uint8, private protos.ProtocolData) protos.ProtocolData {

	trans := drda.getTransaction(tcptuple.Hashable())

    if dir == 1 {

		if trans != nil {
			logp.Err("transaction should be nil for request")
		}

		trans = &DrdaTransaction{Type: "drda", tuple: *tcptuple, TsStart: pkt.Ts}
		drda.transactions.Put(tcptuple.Hashable(), trans)
		logp.Debug("drdadetailed","Initialize transaction")

    } else {
    	if trans == nil {
			logp.Err("transaction should be not nil for response")
    	}
    }

	//dir == 1 request
	//dir == 0 response

	//relevant tcp packet

	defer logp.Recover("ParseDrda exception")

	priv := drdaPrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(drdaPrivateData)
		if !ok {
			priv = drdaPrivateData{}
		}
	}

	if priv.Data[dir] == nil {
		priv.Data[dir] = &DrdaStream{
			tcptuple: tcptuple,
			data:     pkt.Payload,
			message:  &DrdaMessage{},
		}
	} else {
		// concatenate bytes
		priv.Data[dir].data = append(priv.Data[dir].data, pkt.Payload...)
		if len(priv.Data[dir].data) > tcp.TCP_MAX_DATA_IN_STREAM {
			logp.Debug("drda", "Stream data too large, dropping TCP stream")
			priv.Data[dir] = nil
			return priv
		}
	}

	completed := true

	stream := priv.Data[dir]
	for len(stream.data) > 0 {
		if stream.message == nil {
			stream.message = &DrdaMessage{}
		}

		stream.message.Direction = dir

		ok, complete := drdaMessageParser(priv.Data[dir])
		//logp.Debug("drdadetailed", "drdaMessageParser returned ok=%b complete=%b", ok, complete)
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			priv.Data[dir] = nil
			logp.Debug("drdadetailed","Ignore DRDA message. Drop tcp stream. Try parsing with the next segment")
			return priv
		}

		if complete {

			stream.message.TcpTuple = *tcptuple
			stream.message.Direction = dir
			stream.message.CmdlineTuple = procs.ProcWatcher.FindProcessesTuple(tcptuple.IpPort())

			if stream.message.Direction == 1 {
				drda.receivedDrdaRequest(stream.message)
			} else {
				drda.receivedDrdaResponse(stream.message)
			}

	        // and reset message
	        stream.PrepareForNewMessage()
		} else {
			// wait for more data
			completed = false
			break
		}
	}

	if completed {
	    logp.Debug("drdadetailed","Packet with direction %d finished complete", dir)

	    if dir == 0 {
	    	trans.TsEnd = pkt.Ts
	    	drda.publishTransaction(trans)
	        drda.transactions.Delete(trans.tuple.Hashable())

	        logp.Debug("drda", "Drda transaction completed: %s", trans.Requests)
	    }

	} else {
		logp.Debug("drdadetailed","Packet with direction %d finished incomplete", dir)
	}

	return priv
}

func (drda *Drda) GapInStream(tcptuple *common.TcpTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	/*defer logp.Recover("GapInStream(drda) exception")

	if private == nil {
		return private, false
	}
	drdaData, ok := private.(drdaPrivateData)
	if !ok {
		return private, false
	}
	stream := drdaData.Data[dir]
	if stream == nil || stream.message == nil {
		// nothing to do
		return private, false
	}

	if drda.messageGap(stream, nbytes) {
		// we need to publish from here
		drda.messageComplete(tcptuple, dir, stream)
	}

	// we always drop the TCP stream. Because it's binary and len based,
	// there are too few cases in which we could recover the stream (maybe
	// for very large blobs, leaving that as TODO)
	*/

	//TODO: handle GapInStream()

	logp.Err("Unhandled gap of %d bytes in TCP stream",nbytes)

	return private, true
}

func (drda *Drda) ReceivedFin(tcptuple *common.TcpTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	// TODO: check if we have data pending and either drop it to free
	// memory or send it up the stack.
	return private
}

func (drda *Drda) receivedDrdaRequest(msg *DrdaMessage) {
	tuple := msg.TcpTuple
	trans := drda.getTransaction(tuple.Hashable())

	if trans == nil {
		logp.Err("No transaction for this request")
	}

	trans.Src = common.Endpoint{
		Ip:   msg.TcpTuple.Src_ip.String(),
		Port: msg.TcpTuple.Src_port,
		Proc: string(msg.CmdlineTuple.Src),
	}
	trans.Dst = common.Endpoint{
		Ip:   msg.TcpTuple.Dst_ip.String(),
		Port: msg.TcpTuple.Dst_port,
		Proc: string(msg.CmdlineTuple.Dst),
	}
	if msg.Direction == tcp.TcpDirectionReverse {
		trans.Src, trans.Dst = trans.Dst, trans.Src
	}

	if(trans.Requests == nil) {
		trans.Requests = common.MapStr{}
	}

	tmp := common.MapStr{}

	for key, value := range msg.parameters {

		p := common.MapStr{}
		p["desc"] = drda_description[key]
		p["codepoint"] = value.Codepoint
		p["length"] = value.Length
		p["data_ascii"] = value.ASCIIData
		p["data_ebcdic"] = value.EBCDICData
		tmp[drdaAbbrev(key)] = p
    }


	trans.Requests[drdaAbbrev(msg.ddm.Codepoint)] = common.MapStr{

		"description":drda_description[msg.ddm.Codepoint],
		"codepoint": msg.ddm.Codepoint,
		"length2": msg.ddm.Length2,
		"format":msg.ddm.Format,
		"correlation_id": msg.ddm.Cor,
		"length":msg.ddm.Length,
		"direction": msg.Direction,
		"parameters":tmp,
	}

	trans.Notes = msg.Notes
	trans.BytesIn += uint64(msg.ddm.Length)
}

func (drda *Drda) receivedDrdaResponse(msg *DrdaMessage) {
	trans := drda.getTransaction(msg.TcpTuple.Hashable())

	if trans == nil {
		logp.Err("No transaction for this response")
	}

	if(trans.Responses == nil) {
		trans.Responses = common.MapStr{}
	}

	tmp := common.MapStr{}

	for key, value := range msg.parameters {

		p := common.MapStr{}
		p["desc"] = drda_description[key]
		p["codepoint"] = value.Codepoint
		p["length"] = value.Length
		p["data_ascii"] = value.ASCIIData
		p["data_ebcdic"] = value.EBCDICData

		tmp[drdaAbbrev(key)] = p
    }


	trans.Responses[drdaAbbrev(msg.ddm.Codepoint)] = common.MapStr{

		"description":drda_description[msg.ddm.Codepoint],
		"codepoint": msg.ddm.Codepoint,
		"length2": msg.ddm.Length2,
		"format": msg.ddm.Format,
		"correlation_id": msg.ddm.Cor,
		"length":msg.ddm.Length,
		//"direction": msg.Direction,
		"parameters":tmp,
	}

	trans.BytesOut += uint64(msg.ddm.Length)
	trans.Notes = append(trans.Notes, msg.Notes...)
}

func (drda *Drda) publishTransaction(t *DrdaTransaction) {

	if drda.results == nil {
		logp.Err("Nothing to publish")
		return
	}

	t.ResponseTime = int32(t.TsEnd.Sub(t.TsStart).Nanoseconds() / 1e6) // resp_time in milliseconds

	event := common.MapStr{}
	event["type"] = "drda"

	event["responsetime"] = t.ResponseTime
	if drda.Send_request {
		event["request"] = "n.a."//t.Request_raw
	}
	if drda.Send_response {
		event["response"] = "n.a."//t.Response_raw
	}

    event["status"] = common.OK_STATUS
	event["requests"] = t.Requests
	event["reponses"] = t.Responses
	event["bytes_out"] = t.BytesOut
	event["bytes_in"] = t.BytesIn

	if len(t.Notes) > 0 {
		event["notes"] = t.Notes
	}

	event["@timestamp"] = common.Time(t.TsStart)
	event["src"] = &t.Src
	event["dst"] = &t.Dst

	logp.Debug("drda", "Transaction published")

	drda.results.PublishTransaction(event)
}

