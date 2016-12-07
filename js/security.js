/*
* @Author: shine
* @Date:   2016-11-29 15:19:36
* @Last Modified by:   hs
* @Last Modified time: 2016-12-07 09:56:09
* @description 使用Javascript实现前端防御http劫持及防御XSS攻击。
* @version: v1.0.0
*/

'use strict';
(function(window,undefined){
  
  var security = function(){},
      inlineEventMap = {},//内联事件扫描记录
      inlineEventId = 0,//内联事件扫描ID
      scanInlineElement = false;//是否需要扫描内联事件

  //安全域
  var safeList = [
      /([a-zA-Z|a-zA-Z\d])+(\.)+(yy|yystatic)+(\.)+[A-Za-z]{2,14}/g,//*.yy.com
      /((https|http):\/\/)+([a-zA-Z|a-zA-Z\d])+(\.)+(yy|yystatic)+(\.)+[A-Za-z]{2,14}/i,//http开头
      ];
  
  //危险域
  var dangerList = [
      
    ];

  //过滤关键词
  var filterKeyWordList = [
    'BAIDU_DUP_wrapper',//百度推广
    'BAIDU_DSPUI_FLOWBAR'
  ];

  var inlineEventList = [
    'alert',
    'location'
  ];
  /**
   * 过滤指定关键字
   * @param  {[Array]} 过滤词库 
   * @param  {[String]} value    [需要验证的字符串]
   * @return {[Boolean]}         [false -- 验证不通过，true -- 验证通过]
   */
  function filter(list,value){
    if(typeof(value)=='undefined')return true;
    var length = list.length,
      i = 0;

    for (; i < length; i++) {
      // 建立黑名单正则
      var reg = new RegExp(list[i], 'i');

      // 存在黑名单中，拦截
      if (reg.test(value)) {
        return true;
      }
    }
    return false;
  }
  //内联事件劫持
  function inlineEventFilter(){
    var i = 0,
        obj = null;
    
    for (obj in document) {
      if (/^on./.test(obj)) {
        interceptionInlineEvent(obj, i++);
      }
    }
  }

  /**
   * 内联事件拦截
   * @param  {[String]} eventName [内联事件名]
   * @param  {[Number]} eventID   [内联事件id]
   * @return {[type]}             [description]
   */
  function interceptionInlineEvent(eventName, eventID) {
    var isClick = (eventName == 'onclick');

    document.addEventListener(eventName.substr(2), function(e) {
      scanElement(e.target, isClick, eventName, eventID);
    }, true);
  }

  /**
   * 扫描元素是否存在内联事件
   * @param  {[DOM]} elem [DOM元素]
   * @param  {[Boolean]} isClick [是否是内联点击事件]
   * @param  {[String]} eventName [内联 on* 事件名]
   * @param  {[Number]} eventID [给每个内联 on* 事件一个id]
   */
  function scanElement(elem, isClick, eventName, eventID) {
    var flag = elem['isScan'],
        code = "",// 扫描内联代码
        hash = 0;

    // 跳过已扫描的事件
    if (!flag) {
      flag = elem['isScan'] = ++inlineEventId;
    }

    hash = (flag << 8) | eventID;

    if (hash in inlineEventMap) {
      return;
    }

    inlineEventMap[hash] = true;

    // 非元素节点
    if (elem.nodeType != Node.ELEMENT_NODE) {
      return;
    }
    //扫描包括 a iframe img video div 等所有可以写内联事件的元素
    if (elem[eventName]) {
      code = elem.getAttribute(eventName);
      if (code && filter(inlineEventList, code)) {
        // 注销事件
        elem[eventName] = null;
        console.log('拦截可疑内联事件:' + code);
      }
    }

    // 扫描 <a href="javascript:"> 的脚本
    if (isClick && elem.tagName == 'A' && elem.protocol == 'javascript:') {
      var code = elem.href.substr(11);
      if (filter(inlineEventList, code)) {
        // 注销代码
        elem.href = 'javascript:void(0)';
        console.log('拦截可疑事件:' + code);
      }
    }

    // 递归扫描上级元素
    scanElement(elem.parentNode);
  }

  /**
   * 主动防御 MutationEvent
   * 使用 MutationObserver 进行静态插入脚本的拦截
   * @return {[type]} [description]
   */
  function interceptionStaticScript() {
    var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;
    // 该构造函数用来实例化一个新的 Mutation 观察者对象 Mutation 观察者对象能监听在某个范围内的 DOM 树变化
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        var nodes = mutation.addedNodes;

        // 逐个遍历
        for (var i = 0; i < nodes.length; i++) {
          var node = nodes[i];

          // 扫描 script 与 iframe
          if (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME') {
            // 拦截到可疑iframe
            if (node.tagName === 'IFRAME' && node.src && !filter(safeList, node.src)) {
              node.parentNode && node.parentNode.removeChild(node);
              console.log('拦截到可疑iframe', node.src);

            } else if (node.src) {
              // 只放行白名单
              if (!filter(dangerList, node.src)) {
                node.parentNode && node.parentNode.removeChild(node);
                console.log('拦截可疑静态脚本:', node.src);
              }
            }
          }
        }
      });
    });

    // 传入目标节点和观察选项
    // 如果 target 为 document 或者 document.documentElement
    // 则当前文档中所有的节点添加与删除操作都会被观察到d
    observer.observe(document, {
      subtree: true,
      childList: true
    });
  }

  /**
   * 使用 DOMNodeInserted  进行动态脚本拦截监
   * 此处无法拦截，只能监测
   * @return {[type]} [description]
   */
  function interceptionDynamicScript() {
    document.addEventListener('DOMNodeInserted', function(e) {
      var node = e.target;
      
      if (!filter(safeList,node.src) || filter(filterKeyWordList,node.innerHTML)) {
        node.parentNode.removeChild(node);
        console.log('拦截可以创建节点：'+ node.nodeName + ',id为：'+(node.id?node.id:''))
      }
    }, true);
  }

  // 重写 createElement
  function resetCreateElement() {
    // var old_write = window.document.write;

    // var oldcrt = document.createElement;
    // window.Element.prototype.createElement = function(nodeName){

    // }
    // //调用劫持
    // oldcrt.apply(document, arguments);
  }

  /**
   * 重写单个 window 窗口的 document.write 属性
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]}       [description]
   */
  function resetDocumentWrite(window) {
    var old_write = window.document.write;

    window.document.write = function(string) {
      if (filter(filterKeyWordList, string)) {
        console.log('拦截可疑模块:', string);
        return;
      }
      old_write.apply(document, arguments);
    }
  }

  /**
   * 重写单个 window 窗口的 setAttribute 属性
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]} [description]
   */
  function resetSetAttribute(window) {
    var old_setAttribute = window.Element.prototype.setAttribute;

    window.Element.prototype.setAttribute = function(name, value) {
      if (this.tagName == 'SCRIPT' && /^src$/i.test(name)) {
        if (!filter(safeList, value)) {
          console.log('拦截可疑模块:', value);
          return;
        }
      }
      old_setAttribute.apply(this, arguments);
    };
  }

  /**
   * 使用 MutationObserver 对生成的 iframe 页面进行监控，
   * 防止调用内部原生 setAttribute 及 document.write
   * @return {[type]} [description]
   */
  function defenseIframe() {
    // 先保护当前页面
    installHook(window);
  }

  /**
   * 实现单个 window 窗口的 setAttribute保护
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]}       [description]
   */
  function installHook(window) {

    resetSetAttribute(window);
    resetDocumentWrite(window);

    // MutationObserver 的不同兼容性写法
    var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;

    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        var nodes = mutation.addedNodes;

        for (var i = 0; i < nodes.length; i++) {
          var node = nodes[i];

          // 给生成的 iframe 里环境也装上重写的钩子
          if (node.tagName == 'IFRAME') {
            node.contentWindow && installHook(node.contentWindow);
          }
        }
      });
    });

    observer.observe(document, {
      subtree: true,
      childList: true
    });
  }

  /**
   * 使用 Object.defineProperty，锁住call和apply，使之无法被重写
   * @return {[type]} [description]
   */
  function lockCallAndApply() {
    // 锁住 call
    Object.defineProperty(Function.prototype, 'call', {
      value: Function.prototype.call,
      // 当且仅当仅当该属性的 writable 为 true 时，该属性才能被赋值运算符改变
      writable: false,
      // 当且仅当该属性的 configurable 为 true 时，该属性才能够被改变，也能够被删除
      configurable: false,
      enumerable: true
    });
    // 锁住 apply
    Object.defineProperty(Function.prototype, 'apply', {
      value: Function.prototype.apply,
      writable: false,
      configurable: false,
      enumerable: true
    });
  }

  /**
   * 重定向iframe url（页面被iframe包裹）
   */
  function redirectionIframeSrc() {
    var flag = 'iframe_hijack_redirected';//TODO 暂定
    
    if (self != top) {
      var parentUrl = document.referrer,
          length = safeList.length,
          i = 0;

      for (; i < length; i++) {
        // 建立白名单正则
        var reg = new RegExp(safeList[i], 'i');

        // 存在白名单中，放行
        if (reg.test(parentUrl)) {
          return;
        }
      }

      var url = location.href;
      var parts = url.split('#');
      if (location.search) {
        parts[0] += '&' + flag + '=1';
      } else {
        parts[0] += '?' + flag + '=1';
      }
      try {
        console.log('页面被嵌入iframe中:', parentUrl);
        top.location.href = parts.join('#');
      } catch (e) {
        console.log('页面被嵌入iframe中,重定向失败');
      }
    }
  }

    // 初始化方法
  security.init = function() {
    interceptionDynamicScript();

    scanInlineElement && inlineEventFilter();
    
    interceptionStaticScript();

    lockCallAndApply();
  
    defenseIframe();

    redirectionIframeSrc();
  }

  window.httpSecurity = security;
  security.init();
})(window);