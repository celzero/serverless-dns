var CreateError = require('wm-error')
var UsrOperation = require('wm-flagtagoperation')

 var LfuOperation = require('wm-lfu-cache')










function GetSetUserConfig(singleLog,lfu_usr_config_cache_obj,Trie,event,g_var){
	let userConfig = LfuOperation.GetFromCache(singleLog.uid,lfu_usr_config_cache_obj)
	if(!userConfig){
		userConfig = {}
		userConfig.k = singleLog.uid
		data_obj = {}
		data_obj.bl_fl = singleLog.uid
		UsrOperation.UsrFlagToTag(data_obj,Trie)
		UsrOperation.IsUserEnabledServiceTag(data_obj,g_var)
		userConfig.data_obj = data_obj	
	}
	LfuOperation.PushToCache(userConfig,lfu_usr_config_cache_obj,event)
	return userConfig
}

module.exports.GetSetUserConfig = GetSetUserConfig