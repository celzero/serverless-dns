
var SharedContext = require('@celzero/globalcontext').SharedContext
var SingleRequest = require('@celzero/single-request').SingleRequest
var UserOperation = require('@celzero/free-useroperation').UserOperation
var DnsWork = require("@celzero/dns-blocker").DnsWork

addEventListener('fetch', event => {
	event.respondWith(handleRequest(event))
})

async function handleRequest(event) {
	return proxyRequest(event)
}


let commonContext = new SharedContext()
let DnsOperation = new DnsWork()

async function proxyRequest(event) {
	let thisRequest= new SingleRequest()

	var request = event.request
	let res

	let hook = new Hooks()
	try {

		if (request.method === "OPTIONS") {
			res = new Response()
			res.headers.set('Content-Type', 'application/json')
			res.headers.set('Access-Control-Allow-Origin', '*')
			res.headers.set('Access-Control-Allow-Headers', '*')
			return res
		}

		hook.register(LoadGlobalContext, [commonContext,thisRequest])
		hook.register(Command, [commonContext, event, thisRequest])
		hook.register(LoadSingleRequest, [commonContext, event,thisRequest])
		hook.register(LoadCurrentUserConfig, [commonContext, event, thisRequest])
		hook.register(CheckRequestBlock, [commonContext, thisRequest])
		hook.register(ResolveDns, [thisRequest])
		hook.register(CheckCnameBlock, [commonContext, event, thisRequest])
		await hook.call()

	}
	catch (e) {
		//thisRequest.exception = e
		//thisRequest.DnsExceptionResponse()
		res = new Response(JSON.stringify(e.stack))
		res.headers.set('Content-Type', 'application/json')
		res.headers.set('Access-Control-Allow-Origin', '*')
		res.headers.set('Access-Control-Allow-Headers', '*')
		res.headers.append('Vary', 'Origin')
		res.headers.set('server', 'bravedns')
		res.headers.delete('expect-ct')
		res.headers.delete('cf-ray')
		return res
	}

	return thisRequest.httpResponse
}

async function Command(commonContext, event, thisRequest) {
	if (event.request.method === "GET") {
		commonContext.CommandOperation(event.request.url, thisRequest)
	}
	return thisRequest
}

async function LoadGlobalContext(commonContext, thisRequest) {
	if (commonContext.loaded == false) {
		await commonContext.Init(thisRequest)
	}
	return thisRequest
}

async function LoadSingleRequest(commonContext, event, thisRequest) {
	let retryCount = 0;
	let retryLimit = 5;
	while (commonContext.loaded == false) {
		if (retryCount >= retryLimit) {
			break
		}
		await sleep(10)
		retryCount++
	}
	if (commonContext.loaded == true) {
		await thisRequest.Init(event, commonContext)
	}
	return thisRequest
}

async function LoadCurrentUserConfig(commonContext, event, thisRequest) {
	let userWork = new UserOperation()
	userWork.LoadUser(thisRequest, commonContext, event)
	return thisRequest
}


async function ResolveDns(thisRequest) {
	await DnsOperation.ResolveDns(thisRequest)
	return thisRequest
}

async function CheckCnameBlock(commonContext, event, thisRequest) {
	await DnsOperation.CheckResponseCnameDnsBlock(thisRequest, commonContext, event)
	return thisRequest
}


async function CheckRequestBlock(commonContext, thisRequest) {
	DnsOperation.CheckDnsBlock(thisRequest, commonContext)
	return thisRequest
}

const sleep = ms => {
	return new Promise(resolve => {
		setTimeout(resolve, ms);
	});
};

class Hooks {
	constructor() {
		this.hook = []
	}

	register(func, args) {
		this.hook.push({ "func": func, "args": args })
	}

	async call() {
		let response
		for (let i = 0; i <= this.hook.length - 1; i++) {
			response = await this.hook[i].func(...this.hook[i].args)
			if (response.StopProcessing) {
				if (response.IsException) {
					response.DnsExceptionResponse()
				}
				else if (response.IsDnsBlock == true || response.IsCnameDnsBlock == true) {
					response.DnsBlockResponse()
				}
				break
			}
		}
	}
}
