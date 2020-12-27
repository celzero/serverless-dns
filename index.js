var dns = require('wm-dns-packet')
var dnslog = require('./dnslog.js')
var Trie = require('wm-blocklist')
var LfuOperation = require('wm-lfu-cache')
var CreateError = require('wm-error')
var filter = require('wm-filter')
var dnsblocker = require('wm-blocker')
var commonmember = require('wm-common-members')
var useroperation = require('./useroperation.js')
//Global Variable
let lfu_dn_cache_obj
let lfu_usr_config_cache_obj

let g_var = {}
g_var.isloaded = false
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event))
})

async function handleRequest(event) {
  var request = event.request
  console.log("Url : "+request.url)
  console.log("User-agent : "+request.headers.get('user-agent'))
  //console.log("Request : "+ request.headers)
  logh(request.headers)
  return requiresJson(request) ? forwardRequest(request) : proxyRequest(event)
}

function requiresJson(r) {
  return r.method === "GET" &&
    r.headers.get("accept") === "application/dns-json"
}

async function forwardRequest(request) {
  let u = new URL(request.url)
  let res = await forwardDnsJsonMessage(request)
  res = new Response(res.body, res)
  res.headers.set('Access-Control-Allow-Origin', '*')
  res.headers.append('Vary', 'Origin')
  res.headers.set('server', 'bravedns')
  res.headers.set('expect-ct', '')
  res.headers.delete('expect-ct')
  res.headers.delete('cf-ray')
  return res;
}

async function proxyRequest(event) {
	
  let res;
  var Starttime = new Date().getTime()
  var request = event.request
  let usr_config
  try{
	if(event.request.method === "OPTIONS"){
	  res = new Response()
	  res.headers.set('Content-Type', 'application/json')
	  res.headers.set('Access-Control-Allow-Origin', '*')
	  res.headers.set('Access-Control-Allow-Headers','*')
	  return res
	}
	if(g_var.isloaded == false){
		g_var.isloaded = true
		commonmember.LoadGlobalVar(g_var);
	}
    var singleLog = {}
	commonmember.LoadSingleLog(singleLog,event.request,g_var,Trie)
  	
    await filter.check_bloom_sleepneed(singleLog);
	
	await filter.loadFilter(singleLog,event,Trie,g_var)
	
    if(!lfu_dn_cache_obj){
      lfu_dn_cache_obj = new LfuOperation.LruCache("dn_lfu_cache",5000,2,10000,0.00027,0.00001,500,10) //0.4 % false postive, .1mb size
    }

    if(!lfu_usr_config_cache_obj){
      lfu_usr_config_cache_obj = new LfuOperation.LruCache("usr_config_lfu_cache",1000,2,5000,0.00027,0.0001,500,10) //0% false postive
    }
	
	
		
    if(singleLog.uid != "" ){    
		var DnsEncodeObj={}; 
		usr_config = useroperation.GetSetUserConfig(singleLog,lfu_usr_config_cache_obj,Trie,event,g_var)
		await dnsblocker.dnsblock(singleLog,event,Trie,lfu_dn_cache_obj,DnsEncodeObj,filter,usr_config,g_var)
		if(singleLog.isb){
			res = new Response(DnsEncodeObj.responsebuf)
		}
		else{      
			res = await forwardDnsMessage(event.request)
			await dnsblocker.cname_dnsblock(singleLog,event,Trie,lfu_dn_cache_obj,DnsEncodeObj,res,filter,usr_config,g_var)
			if(!singleLog.isb){
				res = new Response(res.body, res)
			}
			else{
				res = new Response(DnsEncodeObj.responsebuf)
			}
		}	  	           
		singleLog.time = new Date().getTime() - Starttime	
		res.headers.set('x-nile-flags', singleLog.bl_flag)		
		//PushDnsLog(dnslog,singleLog,event,true)
		//PushDnsCount(dnslog,event,singleLog.uid)	
		//res = new Response(JSON.stringify(singleLog)) 		
    }
    else{
		res = await forwardDnsMessage(event.request)
		res = new Response(res.body, res) 			  
    }
  }
  catch(e){	  
	console.log(e.stack)
    singleLog.IsErr = true;
    singleLog.Err = e.message
	singleLog.errstack = e.stack
	DnsEncodeObj = dns.encode({
			type: 'response',
			flags: 1
			});
    res = new Response(DnsEncodeObj)
    res = new Response(res.body, res)
	res.headers.set('x-err', JSON.stringify(singleLog))
    //res = new Response(JSON.stringify(singleLog))        
  }
  res.headers.set('Content-Type', 'application/dns-message')
  res.headers.set('Access-Control-Allow-Origin', '*')
  res.headers.set('Access-Control-Allow-Headers','*')
  res.headers.append('Vary', 'Origin')
  res.headers.delete('expect-ct')
  res.headers.delete('cf-ray')
  return res
}
function remove_log_variable(singleLog){
	delete singleLog.flow
	delete singleLog.bl_flag
}

function PushDnsLog(dnslog,singleLog,event,to_log){
	if(to_log){
		remove_log_variable(singleLog)
		dnslog.LogObj.DNSBulkLog.push(singleLog)
		if(!dnslog.LogObj.logblock){
			event.waitUntil(dnslog.logThreadBlock())
		}
	}
}

function PushDnsCount(dnslog,event,ckey){
	let obj = dnslog.DnsCountObj.DNSCount.get(ckey)
	if(obj){
		obj.count++
	}
	else{
		obj = {}
		obj.count = 1
		obj.dt = new Date().toISOString()
		obj.ckey = ckey
		dnslog.DnsCountObj.DNSCount.set(ckey,obj)
	}
	if(!dnslog.DnsCountObj.block){
		event.waitUntil(dnslog.dnscountThreadBlock())
	}	
}
async function forwardDnsMessage(request) {
  let u = new URL(request.url)
  u.hostname = "cloudflare-dns.com"
  u.pathname = "dns-query"

  request = new Request(u.href, request)
  request.headers.set('accept', 'application/dns-message')
  request.headers.set('content-type', 'application/dns-message')
  request.headers.set('Origin', u.origin)


  return await fetch(request)
}

async function forwardDnsMessage_notSafesearch(request) {
  let u = new URL(request.url)
  u.hostname = "1.1.1.3"
  u.pathname = "dns-query"

  request = new Request(u.href, request)
  request.headers.set('accept', 'application/dns-message')
  request.headers.set('content-type', 'application/dns-message')
  request.headers.set('Origin', u.origin)


  return await fetch(request)
}

async function forwardDnsJsonMessage(request) {
  let u = new URL(request.url)
  u.hostname = "cloudflare-dns.com"
  u.pathname = "dns-query"
  request = new Request(u.href, request)
  request.headers.set('accept', 'application/dns-json')
  request.headers.set('Origin', u.origin)

  return await fetch(request)
}

function getParam(url, key) {
  return url.searchParams.get(key)
}

function logh(h) {
  for (let p of h) console.log(p)
}



