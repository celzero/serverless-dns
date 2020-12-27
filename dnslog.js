var CreateError = require('wm-error')
 

 //log code starts
var LogObj = {}
LogObj.logblock = false
LogObj.DNSBulkLog = []

var DnsCountObj = {}
DnsCountObj.DNSCount = new Map()
DnsCountObj.block = false

async function logThreadBlock(){
  try{
    LogObj.logblock = true
    await sleep(kv_var_dnslog_waittime)
    await PushLogtoServer()  
    LogObj.logblock = false
  }
  catch(e){
    LogObj.logblock = false
    //manage event.waituntil exception here
  }
}

async function dnscountThreadBlock(){
  try{    
	DnsCountObj.block = true
    await sleep(kv_var_dnscount_waittime) 
	await PushDnsCounttoServer()
    DnsCountObj.block = false
  }
  catch(e){
    DnsCountObj.block = false
    //manage event.waituntil exception here
  }
}
const sleep = ms => {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
};

async function PushLogtoServer(){
  try{
    var jsonLogString = ""
    LogObj.DNSBulkLog.forEach(function(data){
        jsonLogString = jsonLogString+JSON.stringify(data)+"\n"
    })
	LogObj.DNSBulkLog = []
    //add your logic here to handle dns-logs from jsonLogString variable delimited by \n
  }
  catch(e){
    CreateError.CreateError("dnslog.js PushLogtoServer - ",e)
  }
}

async function PushDnsCounttoServer(){
  try{
    var jsonLogString = ""
    DnsCountObj.DNSCount.forEach(function(value){
        jsonLogString = jsonLogString+JSON.stringify(value)+"\n"
    })
	DnsCountObj.DNSCount = new Map()
    //add your logic here to handle dns-logs-count from jsonLogString variable delimited by \n  
  }
  catch(e){
    CreateError.CreateError("dnslog.js PushDnsCounttoServer - ",e)
  }
}

module.exports.logThreadBlock = logThreadBlock
module.exports.LogObj = LogObj
module.exports.dnscountThreadBlock = dnscountThreadBlock
module.exports.DnsCountObj = DnsCountObj