package decomp

// envJS 为编译产物（page-frame）提供最小可运行的宿主环境。
//
// 编译后的 WXML 是一段自执行的 JS：它定义 $gwx_<appid>(path, global) 工厂，
// 调用后返回 function(env, dd, global)，用数据作用域 env 求值出虚拟 DOM 树。
// 因此还原 WXML 必须真正执行这段代码，而不是静态解析。
//
// 这里的关键是 __env()/__mk() 构造的 Proxy 哨兵：任意属性访问都返回可继续
// 展开的对象，并在被字符串化时吐出 "@@WX:<路径>"。这样求值结果里就带回了
// 原始绑定路径（如 "@@WX:item.title" → {{item.title}}），而不是 undefined。
const envJS = `
var __SWALLOW=[];
var console={warn:function(){},error:function(){},info:function(){},
  log:function(){__SWALLOW.push(Array.prototype.slice.call(arguments).join(' '))}};
var setTimeout=function(){},setInterval=function(){},clearTimeout=function(){},clearInterval=function(){};
var navigator={userAgent:'wxsec'};
var location={href:'about:blank',protocol:'https:',host:'',search:''};
var screen={width:375,height:812,availWidth:375,availHeight:812};
var innerWidth=375,innerHeight=812,devicePixelRatio=2;

// __STYLE_ELS__ 记录宿主创建的 style 节点。
//
// 编译后的 WXSS 不会以字符串形式留在 __wxAppCode__ 里：setCssToHead(数组)() 把
// 拼接好的样式写进一个真实的 <style> 元素（styleSheet.cssText 或文本子节点），
// 赋给 __wxAppCode__ 的是 undefined。因此必须从 DOM 桩里把这些节点收回来，
// 否则整个包的 WXSS 都会还原不出来。
var __STYLE_ELS__=[];
function __el(tag){
  return {style:{},childNodes:[],children:[],parentNode:null,
    tagName:(tag||'DIV').toUpperCase(),nodeType:1,attrs:{},styleSheet:{cssText:''},
    innerHTML:'',textContent:'',length:0,namespaceURI:'http://www.w3.org/1999/xhtml',
    setAttribute:function(k,v){this.attrs[k]=v},
    getAttribute:function(k){return Object.prototype.hasOwnProperty.call(this.attrs,k)?this.attrs[k]:null},
    removeAttribute:function(k){delete this.attrs[k]},
    appendChild:function(c){this.childNodes.push(c);
      if(this.tagName==='STYLE'&&c&&c.nodeType===3){this.textContent+=(c.textContent||'')}
      return c},
    insertBefore:function(c){this.childNodes.push(c);return c},
    removeChild:function(c){return c},
    addEventListener:function(){},removeEventListener:function(){},
    querySelector:function(){return null},querySelectorAll:function(){return []},
    getElementById:function(){return null},getElementsByTagName:function(){return []},
    getElementsByClassName:function(){return []},
    cloneNode:function(t){return __el(t&&t.tagName?t.tagName:'DIV')},contains:function(){return false}};
}
var document={
  createElement:function(t){var e=__el(t); if(String(t).toLowerCase()==='style') __STYLE_ELS__.push(e); return e;},
  createElementNS:function(ns,t){var e=__el(t); if(String(t).toLowerCase()==='style') __STYLE_ELS__.push(e); return e;},
  createTextNode:function(t){return {nodeType:3,textContent:t,data:t,nodeValue:t}},
  createComment:function(t){return {nodeType:8,textContent:t||''}},
  createDocumentFragment:__el,documentElement:__el(),head:__el(),body:__el(),
  addEventListener:function(){},removeEventListener:function(){},
  querySelector:function(){return null},querySelectorAll:function(){return []},
  getElementById:function(){return null},getElementsByTagName:function(){return []},
  getElementsByClassName:function(){return []}};

var __wxAppCode__={};
var __WXML_GLOBAL__={entrys:{},defines:{},modules:{},ops:[],wxs_nf_init:undefined,total_ops:0};
var window=this; var self=this;
window.__wxAppCode__=__wxAppCode__;
window.__WXML_GLOBAL__=__WXML_GLOBAL__;
window.document=document; window.navigator=navigator;
window.location=location; window.screen=screen; window.console=console;

// 模块包装器与小程序 API 桩。
//
// 插件与分包代码被包在 define/definePlugin('plugin://wxAPPID', function(define,
// require, module, exports, global, wx, App, Page, Component, Behavior, getApp,
// getCurrentPages, console, requireMiniProgram, WXWebAssembly, __wxCodeSpace__){…})
// 里，插件自己的 $gwx_<APPID> 工厂就定义在该回调内部。把 define/definePlugin
// 桩成空函数会让这些工厂永远不存在，整个插件的模板都还原不出来，因此必须真正
// 执行回调；回调内部报错只丢弃该模块，不影响其余模板。
var __modules = {};
function __noop() {}
function __mod() { return {exports: {}} }
function __runFactory(f) {
  if (typeof f !== 'function') return;
  try {
    var m = __mod();
    f(define, require, m, m.exports, globalThis, wx, __noop, __noop, __noop, __noop,
      getApp, getCurrentPages, console, require, function() { return {} }, {});
  } catch (e) {
    __SWALLOW.push('module factory: ' + (e && e.message ? e.message : e));
  }
}
function define(name, f) { __modules[name] = f; __runFactory(f); }
function definePlugin(name, f) { __modules[name] = f; __runFactory(f); }
var require = function() { return {} },
    requirePlugin = function() { return {} }, requireNativePlugin = function() { return {} },
    PluginRequires = function() { return {} }, getRegExp = function() { return new RegExp() },
    getApp = function() { return {} }, getCurrentPages = function() { return [] },
    WeixinJSBridge = {invoke: function() {}}, __wxRoute = '', __wxAppCurrentFile__ = '',
    __vd_version_info__ = {globalThis: globalThis};
var wx = {
  getSystemInfoSync: function() { return {windowWidth:375, screenWidth:375, pixelRatio:2, platform:'devtools'} },
  env: {USER_DATA_PATH: '/usr'},
  getStorageSync: function() { return '' }, setStorageSync: function() {},
  canIUse: function() { return false }, onError: function() {}, nextTick: function() {}
};

var __SENT='@@WX:';
function __mk(tag){
  return new Proxy(function(){}, {
    get:function(t,p){
      var ps=String(p);
      if(typeof p==='symbol'){
        if(ps==='Symbol(Symbol.toPrimitive)') return function(){return __SENT+tag};
        return undefined;
      }
      if(p==='valueOf'||p==='toString') return function(){return __SENT+tag};
      if(p==='toJSON') return function(){return __SENT+tag};
      if(p==='then'||p==='length') return undefined;
      return __mk(tag+'.'+ps);
    },
    apply:function(){return __mk(tag+'()')},
    construct:function(){return __mk(tag+'#')}
  });
}
function __env(){
  return new Proxy({},{
    get:function(t,p){
      if(typeof p==='symbol') return undefined;
      if(p==='length') return undefined;
      return __mk(String(p));
    },
    has:function(){return true},
    ownKeys:function(){return []},
    getOwnPropertyDescriptor:function(){return {enumerable:true,configurable:true}},
    set:function(){return true}
  });
}

// __render 渲染单个模板为 JSON 树；useProxy 为真时用哨兵作用域求值。
function __render(gname, rel, useProxy){
  var f = globalThis[gname](rel, __WXML_GLOBAL__);
  if (!f) throw new Error('no compiled entry: ' + rel);
  var root = useProxy ? f(__env(), {}, {}) : f(undefined, {}, {});
  return JSON.stringify(root);
}

// __deps 取出 __WXML_DEP__：模板路径 → 其正文实际编译进的依赖模板列表。
function __deps(){
  var d = (typeof __WXML_DEP__ === 'undefined' || !__WXML_DEP__) ? {} : __WXML_DEP__;
  return JSON.stringify(d);
}

// __styles 取出编译产物中的 WXSS 字符串。
//
// 两种写法都要处理：app.wxss 之类在加载时就自执行成 <style> 元素；页面级 WXSS 注册的是
// setCssToHead(...) 返回的闭包（结尾没有 ()），不主动调用一次就永远拿不到样式文本。
function __styles(){
  var out={};
  var keys=Object.keys(__wxAppCode__);
  for (var i=0;i<keys.length;i++){
    var v=__wxAppCode__[keys[i]];
    if (typeof v==='string'){ out[keys[i]]=v; }
    else if (typeof v==='function' && /\.wxss$/.test(keys[i])) {
      try { v('', {}, undefined); } catch (e) { __SWALLOW.push('wxss: '+(e&&e.message?e.message:e)); }
    }
  }
  for (var j=0;j<__STYLE_ELS__.length;j++){
    var el=__STYLE_ELS__[j];
    var p=el.getAttribute('wxss:path');
    if (!p||out[p]) continue;
    var css=(el.styleSheet&&el.styleSheet.cssText)?el.styleSheet.cssText:(el.textContent||'');
    if (css) out[p]=css;
  }
  return JSON.stringify(out);
}
`
