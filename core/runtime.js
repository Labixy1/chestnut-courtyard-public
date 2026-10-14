(function(){
  if(window.CozyRuntime)return;
  const VALID_MODES=new Set(['owner','selfhost','interview','preview','dev']);
  const configured=Object.assign({},window.COZY_RUNTIME_CONFIG||{});
  const query=new URLSearchParams(location.search).get('cozy_mode');
  function autoMode(){
    if(location.protocol==='file:')return 'dev';
    if(['127.0.0.1','localhost','::1'].includes(location.hostname))return 'dev';
    return 'preview';
  }
  const requested=VALID_MODES.has(query)?query:configured.mode;
  const mode=VALID_MODES.has(requested)?requested:autoMode();
  const staticHosting=configured.staticHosting===true;
  const readOnly=staticHosting||mode==='preview'||configured.allowWrites===false;
  const source=configured.dataSource==='auto'?(mode==='dev'?'local':'bundle'):configured.dataSource;
  const apiBase=location.protocol==='file:'?'http://127.0.0.1:8766':String(configured.apiBase||'');
  const keyForPath=path=>String(path||'').split('/').pop().replace(/\.json$/,'');
  const clone=value=>JSON.parse(JSON.stringify(value));
  async function loadJson(path,fallback,key){
    const dataKey=key||keyForPath(path);
    const bundled=window.COZY&&window.COZY[dataKey];
    if(source==='bundle'||location.protocol==='file:')return clone(bundled===undefined?fallback:bundled);
    try{
      const target=source==='remote'
        ? apiBase+'/api/data?key='+encodeURIComponent(dataKey)
        : path;
      const response=await fetch(target,{
        cache:source==='remote'?'no-store':'default',
        credentials:'same-origin',
        headers:{'accept':'application/json'}
      });
      if(!response.ok)throw new Error('HTTP '+response.status);
      return await response.json();
    }catch(error){
      return clone(bundled===undefined?fallback:bundled);
    }
  }
  function seedDemoBrowserState(force=false){
    if(mode!=='interview'||configured.demoStaticSeed!==true)return false;
    const values=window.COZY?.local_state?.values;
    if(!values||typeof values!=='object')return false;
    const version=String(window.COZY?.local_state?.version||1);
    const upgrade=localStorage.getItem('cozy_demo_seed_version')!==version;
    Object.entries(values).forEach(([key,value])=>{
      if(force||upgrade||localStorage.getItem(key)===null)localStorage.setItem(key,JSON.stringify(clone(value)));
    });
    localStorage.setItem('cozy_demo_seed_version',version);
    return true;
  }
  seedDemoBrowserState(false);
  function assertWritable(){if(readOnly)throw new Error('当前是公开预览，只能浏览，数据不会写入');}
  window.CozyRuntime=Object.freeze({
    mode,readOnly,staticHosting,dataSource:source,apiBase,demoStaticSeed:configured.demoStaticSeed===true,
    appName:String(configured.appName||'阿栗'),
    instanceId:String(configured.instanceId||mode),
    loadJson,assertWritable,seedDemoBrowserState,
    capabilities:Object.freeze({
      ai:!readOnly,memory:!readOnly,upload:!readOnly,
      systemChange:!readOnly&&(mode==='owner'||mode==='dev')
    })
  });
  document.documentElement.dataset.cozyMode=mode;
  window.dispatchEvent(new CustomEvent('cozy:runtime-ready',{detail:window.CozyRuntime}));
  if(staticHosting&&typeof document.addEventListener==='function'){
    // Static Pages has no API: keep navigation usable without pretending writes work.
    const actions=new Set(['saveTrip','saveTripEdits','removeTrip','removeTripPhoto','pickTripPhotos','pickNewTripPhotos','saveReflection','deleteReflection','summarizeReflection','startReflectionVoice','saveNoticeNote','deleteNoticeNote','toggleNoticeReadLater','openChestPicker','extractToolFromNotice','parseNoticeRequestLink','refreshBlackboardQuestion','submitBbAnswer','askBlackboardHelper','saveBlackboardDirection','reopenBbAnswer','startVoice','addEntry','saveHeartEntryEdit','deleteHeartEntry','saveBuriedText','deleteBuriedItem','chooseBuriedPhoto','generateBuriedImage','plantSeed','toggleOrchardVoice','startNewOrchardChat','waterAllPlots','harvestAllPlots','waterSinglePlot','harvestPlot','waterPlot','startDistillation','distillMemory','forgetMemory','undoSnapshot','createPhotoAlbum','renamePhotoAlbum','deletePhotoAlbum','removeAlbumPhoto','refreshToolPrice']);
    function locks(button){return String(button.getAttribute('onclick')||'').match(/\b[A-Za-z]+(?=\()/g)?.some(name=>actions.has(name))||['notice-refresh','orchard-plant','seed-mic','distill-button'].includes(button.id);}
    function lockControls(){
      document.querySelectorAll('button,input,textarea').forEach(node=>{
        if(node.tagName==='BUTTON'&&locks(node)){node.disabled=true;node.title='静态演示不提交修改；实时功能需要部署 Worker';}
        if(node.tagName==='TEXTAREA'||node.tagName==='INPUT'){
          if(['file','date','password'].includes(node.type))node.disabled=true;
          else node.readOnly=true;
        }
      });
      document.querySelectorAll('.notice-note-state').forEach(node=>{if(node.textContent.includes('私人云端'))node.textContent='示例阅读笔记';});
    }
    function initLocks(){lockControls();new MutationObserver(lockControls).observe(document.body,{childList:true,subtree:true});}
    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initLocks);else initLocks();
  }
})();
