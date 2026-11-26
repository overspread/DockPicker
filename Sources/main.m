#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <Security/AuthSession.h>
#import <ApplicationServices/ApplicationServices.h>
#import <objc/runtime.h>

// DockPicker runtime integration. No target bundle writes, signing, chown,
// privilege escalation, injection, replacement Dock, or overlay windows.
// The LaunchServices notification is kept separate from the application's
// activation policy; Dock bookkeeping may still be updated by the system.

// 长期保存用户的隐藏选择；PID 和重试时间仅用于本次运行，不能随应用退出删除规则。
static NSString *const HiddenPathsKey=@"runtime.hiddenApplicationPaths.v2";
static NSString *const HiddenPidsKey=@"runtime.hiddenApplicationPids.v2";
static const void *EntryKey=&EntryKey;
static id AXValue(AXUIElementRef e,CFStringRef k){AXUIElementSetMessagingTimeout(e,0.08f);CFTypeRef v=NULL;return AXUIElementCopyAttributeValue(e,k,&v)==kAXErrorSuccess?CFBridgingRelease(v):nil;}
static void CollectDockPaths(AXUIElementRef e,int depth,NSMutableSet *paths){
 if(depth>4)return;
 id subrole=AXValue(e,kAXSubroleAttribute);
 if([subrole isKindOfClass:[NSString class]]&&[subrole isEqualToString:@"AXApplicationDockItem"]){id u=AXValue(e,kAXURLAttribute);if([u isKindOfClass:[NSURL class]])[paths addObject:[u path]];}
 id children=AXValue(e,kAXChildrenAttribute);
 if(![children isKindOfClass:[NSArray class]])return;
 for(id child in (NSArray*)children){if(CFGetTypeID((__bridge CFTypeRef)child)!=AXUIElementGetTypeID())continue;CollectDockPaths((__bridge AXUIElementRef)child,depth+1,paths);}
}
static NSSet *ReadDockPaths(void){
 if(!AXIsProcessTrusted())return nil;
 NSMutableSet *paths=[NSMutableSet set];
 for(NSRunningApplication *a in [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.dock"]){AXUIElementRef e=AXUIElementCreateApplication(a.processIdentifier);CollectDockPaths(e,0,paths);CFRelease(e);}
 return paths.count?paths:nil;
}
static BOOL sDockReadInFlight=NO;
static CFTimeInterval sLastDockRead=0;
static NSUInteger sDockReadGeneration=0;
static NSSet *sCachedDockPaths=nil;
static NSSet *VisibleDockPaths(void){
  if(!AXIsProcessTrusted())return nil;
  @synchronized([NSRunningApplication class]){
    CFTimeInterval now=CFAbsoluteTimeGetCurrent();
    if(!sDockReadInFlight&&now-sLastDockRead>=0.25){
      sDockReadInFlight=YES;sLastDockRead=now;
      NSUInteger generation=sDockReadGeneration;
      dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        NSSet *fresh=ReadDockPaths();
        @synchronized([NSRunningApplication class]){if(generation==sDockReadGeneration)sCachedDockPaths=fresh;sDockReadInFlight=NO;}
      });
    }
    return sCachedDockPaths;
  }
}
// 带超时执行子进程：lsappinfo 挂住时不再让 busy 永真、锁死面板与退出。
static BOOL RunTask(NSTask *task,NSTimeInterval timeout,NSData **output,NSString **error){
 NSPipe *pipe=[NSPipe pipe];task.standardOutput=pipe;task.standardError=pipe;
 dispatch_semaphore_t done=dispatch_semaphore_create(0);
 task.terminationHandler=^(NSTask *t){dispatch_semaphore_signal(done);};
 NSError *launchError=nil;
 if(![task launchAndReturnError:&launchError]){if(error)*error=launchError.localizedDescription?:@"命令无法启动。";return NO;}
 if(dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,(int64_t)(timeout*NSEC_PER_SEC)))!=0){
  [task terminate];
  if(dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,(int64_t)NSEC_PER_SEC))!=0){if(error)*error=@"命令无响应，已放弃等待。";return NO;}
  if(output)*output=[pipe.fileHandleForReading readDataToEndOfFile];
  if(error)*error=@"命令超时，已终止。";
  return NO;
 }
 if(output)*output=[pipe.fileHandleForReading readDataToEndOfFile];
 return YES;
}
static BOOL SendRuntimeNotification(NSDictionary *entry,BOOL shown,NSString **error){
 pid_t pid=[entry[@"pid"]intValue];
 NSRunningApplication *app=[NSRunningApplication runningApplicationWithProcessIdentifier:pid];
 if(!app||app.terminated)return YES;
 if(![app.bundleURL.path isEqualToString:entry[@"path"]]||![app.bundleIdentifier isEqualToString:entry[@"bundle"]]){if(error)*error=@"应用进程已改变，请刷新后重试。";return NO;}
 if(app.activationPolicy!=NSApplicationActivationPolicyRegular){if(error)*error=@"应用自身已处于后台模式；本工具不会改变它的真实类型。";return NO;}
 ProcessSerialNumber psn={0,0};
 if(GetProcessForPID(pid,&psn)!=noErr){if(error)*error=@"无法读取该运行进程的标识。";return NO;}
 SecuritySessionId session=0;SessionAttributeBits attributes=0;
 if(SessionGetInfo(callerSecuritySession,&session,&attributes)!=noErr){if(error)*error=@"无法读取当前登录会话。";return NO;}
 NSString *asn=[NSString stringWithFormat:@"ASN:0x%x-0x%x:",(unsigned)psn.highLongOfPSN,(unsigned)psn.lowLongOfPSN];
 NSTask *task=[NSTask new];task.executableURL=[NSURL fileURLWithPath:@"/usr/bin/lsappinfo"];
 task.arguments=@[@"-sessionID",[@(session)stringValue],@"send",@"appTypeChanged",@"-asn",asn,
  shown?@"kLSApplicationTypeKey=kLSApplicationForegroundTypeKey":@"kLSApplicationTypeKey=kLSApplicationUIElementTypeKey",
  shown?@"kLSPreviousValueKey=kLSApplicationUIElementTypeKey":@"kLSPreviousValueKey=kLSApplicationForegroundTypeKey"];
 NSData *output=nil;NSString *taskError=nil;
 if(!RunTask(task,5,&output,&taskError)){if(error)*error=taskError?:@"通知发送失败。";return NO;}
 if(task.terminationStatus!=0){if(error)*error=[[NSString alloc]initWithData:output encoding:NSUTF8StringEncoding]?:@"通知发送失败。";return NO;}
 return YES;
}
// 操作后在工作线程读取新状态，避免把发送请求前的缓存当成执行结果。
static BOOL WaitForDockState(NSArray *entries,BOOL shown,NSTimeInterval timeout,NSSet **dockPaths){
 NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:timeout];
 NSSet *visible=nil;
 while(YES){
  visible=ReadDockPaths();
  if(visible){
   BOOL settled=YES;
   for(NSDictionary *entry in entries){
    NSRunningApplication *app=[NSRunningApplication runningApplicationWithProcessIdentifier:[entry[@"pid"]intValue]];
    if(!app||app.terminated)continue;
    if([visible containsObject:entry[@"path"]]!=shown){settled=NO;break;}
   }
   if(settled)break;
  }
  if([deadline timeIntervalSinceNow]<=0)break;
  [NSThread sleepForTimeInterval:.2];
 }
 @synchronized([NSRunningApplication class]){sDockReadGeneration++;sCachedDockPaths=visible;sLastDockRead=CFAbsoluteTimeGetCurrent();}
 if(dockPaths)*dockPaths=visible;
 return visible!=nil;
}

@interface ApplicationRow:NSTableCellView
@property(strong) NSImageView *appIcon;
@property(strong) NSTextField *nameLabel;
@property(strong) NSTextField *detailLabel;
@property(strong) NSSwitch *visibilitySwitch;
@end
@implementation ApplicationRow
- (instancetype)initWithFrame:(NSRect)frame{if((self=[super initWithFrame:frame])){
 self.identifier=@"ApplicationRow";
 _appIcon=[NSImageView new];_appIcon.imageScaling=NSImageScaleProportionallyDown;
 _nameLabel=[NSTextField labelWithString:@""];_nameLabel.font=[NSFont systemFontOfSize:13 weight:NSFontWeightMedium];
 _detailLabel=[NSTextField labelWithString:@""];_detailLabel.font=[NSFont systemFontOfSize:10];_detailLabel.textColor=NSColor.secondaryLabelColor;
 _nameLabel.lineBreakMode=NSLineBreakByTruncatingTail;_detailLabel.lineBreakMode=NSLineBreakByTruncatingMiddle;
 _visibilitySwitch=[NSSwitch new];_visibilitySwitch.toolTip=@"开启：显示并取消自动隐藏；关闭：持续隐藏，应用重开后自动再次隐藏（需要 DockPicker 保持运行）。";
 for(NSView *v in @[_appIcon,_nameLabel,_detailLabel,_visibilitySwitch]){v.translatesAutoresizingMaskIntoConstraints=NO;[self addSubview:v];}
 [NSLayoutConstraint activateConstraints:@[
  [_appIcon.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:10],[_appIcon.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],[_appIcon.widthAnchor constraintEqualToConstant:28],[_appIcon.heightAnchor constraintEqualToConstant:28],
  [_nameLabel.leadingAnchor constraintEqualToAnchor:_appIcon.trailingAnchor constant:11],[_nameLabel.topAnchor constraintEqualToAnchor:self.topAnchor constant:7],[_nameLabel.trailingAnchor constraintLessThanOrEqualToAnchor:_visibilitySwitch.leadingAnchor constant:-14],
  [_detailLabel.leadingAnchor constraintEqualToAnchor:_nameLabel.leadingAnchor],[_detailLabel.topAnchor constraintEqualToAnchor:_nameLabel.bottomAnchor constant:2],[_detailLabel.trailingAnchor constraintLessThanOrEqualToAnchor:_visibilitySwitch.leadingAnchor constant:-14],
  [_visibilitySwitch.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-12],[_visibilitySwitch.centerYAnchor constraintEqualToAnchor:self.centerYAnchor]
 ]];
 }return self;}
@end

@interface AppDelegate:NSObject<NSApplicationDelegate,NSTableViewDataSource,NSTableViewDelegate,NSSearchFieldDelegate,NSMenuDelegate>
@property(strong) NSWindow *window;
@property(strong) NSTableView *table;
@property(strong) NSSearchField *search;
@property(strong) NSTextField *status;
@property(strong) NSButton *refreshButton;
@property(strong) NSButton *restoreButton;
@property(strong) NSStatusItem *statusItem;
@property(strong) NSArray<NSDictionary*> *entries;
@property(strong) NSArray<NSDictionary*> *allEntries;
@property(strong) NSSegmentedControl *filterControl;
@property(strong) NSMutableSet<NSString*> *hiddenPaths;
@property(strong) NSMutableDictionary<NSString*,NSNumber*> *hiddenPids;
@property(strong) NSMutableDictionary<NSString*,NSDate*> *hiddenSince;
@property(strong) NSSet<NSString*> *dockPaths;
@property BOOL busy;
@property(strong) NSMutableSet<NSString*> *acceptedPaths;
@property(copy) NSDictionary<NSString*,NSNumber*> *pendingMenuStates;
@property(copy) NSString *operationMessage;
@end
@implementation AppDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)n{
 [[NSUserDefaults standardUserDefaults]removeObjectForKey:@"runtime.hiddenApplicationPaths"];
 [[NSUserDefaults standardUserDefaults]removeObjectForKey:HiddenPidsKey];
 self.hiddenPaths=[NSMutableSet setWithArray:[[NSUserDefaults standardUserDefaults]arrayForKey:HiddenPathsKey]?:@[]];self.hiddenPids=[NSMutableDictionary dictionary];self.hiddenSince=[NSMutableDictionary dictionary];self.acceptedPaths=[NSMutableSet set];
 self.entries=@[];[self buildMainMenu];[self buildWindow];[self buildStatusMenu];[self reload:nil];[self showPanel:nil];
 [[NSNotificationCenter defaultCenter]addObserver:self selector:@selector(searchChanged:) name:NSControlTextDidChangeNotification object:self.search];
 [[NSNotificationCenter defaultCenter]addObserver:self selector:@selector(appDidBecomeActive:) name:NSApplicationDidBecomeActiveNotification object:nil];
 [[NSNotificationCenter defaultCenter]addObserver:self selector:@selector(appDidResignActive:) name:NSApplicationDidResignActiveNotification object:nil];
 [NSWorkspace.sharedWorkspace.notificationCenter addObserver:self selector:@selector(workspaceApplicationDidLaunch:) name:NSWorkspaceDidLaunchApplicationNotification object:nil];
 [NSTimer scheduledTimerWithTimeInterval:3 target:self selector:@selector(timerRefresh:) userInfo:nil repeats:YES];
 [self applyHiddenChoices];
}
- (NSArray<NSDictionary*>*)runningEntries{
 NSMutableArray *rows=[NSMutableArray array];NSString *own=NSBundle.mainBundle.bundleIdentifier;
 NSString *userApps=[NSHomeDirectory()stringByAppendingPathComponent:@"Applications/"];
 for(NSRunningApplication *app in NSWorkspace.sharedWorkspace.runningApplications){
  NSString *path=app.bundleURL.path;NSString *bid=app.bundleIdentifier;
  if(!path||!bid||[bid isEqualToString:own]||app.terminated)continue;

  BOOL supported=[path hasPrefix:@"/Applications/"]||[path hasPrefix:@"/System/Applications/"]||[path hasPrefix:userApps];
  if(!supported||[path containsString:@"/Contents/"])continue;
  if(app.activationPolicy!=NSApplicationActivationPolicyRegular)continue;
  [rows addObject:@{@"path":path,@"bundle":bid,@"pid":@(app.processIdentifier),@"name":app.localizedName?:app.bundleURL.lastPathComponent.stringByDeletingPathExtension}];
 }
 [rows sortUsingComparator:^NSComparisonResult(NSDictionary*a,NSDictionary*b){return[a[@"name"]localizedCaseInsensitiveCompare:b[@"name"]];}];
 return rows;
}
- (void)saveChoices{
 NSUserDefaults *u=[NSUserDefaults standardUserDefaults];
 [u setObject:self.hiddenPaths.allObjects forKey:HiddenPathsKey];
 [u removeObjectForKey:HiddenPidsKey];
 [u synchronize];
}
- (void)reconcileHiddenPaths:(NSArray<NSDictionary*>*)running{
 NSMutableDictionary *livePids=[NSMutableDictionary dictionary];
 for(NSDictionary *entry in running)livePids[entry[@"path"]]=entry[@"pid"];
 // 只回收进程状态，保留长期规则；应用重开后要对新 PID 再执行隐藏。
 for(NSString *path in self.hiddenPids.allKeys){
  if([self.hiddenPaths containsObject:path]&&[self.hiddenPids[path]isEqual:livePids[path]])continue;
  [self.hiddenPids removeObjectForKey:path];[self.hiddenSince removeObjectForKey:path];
 }
}
- (void)applyHiddenChoices{
 // 后台自动执行不弹授权框，也不与用户操作并发。
 if(self.busy||self.hiddenPaths.count==0||!AXIsProcessTrusted())return;
 NSArray *running=[self runningEntries];[self reconcileHiddenPaths:running];
 NSSet *visible=VisibleDockPaths();NSDate *now=[NSDate date];
 NSMutableArray *targets=[NSMutableArray array];
 for(NSDictionary *entry in running){
  NSString *path=entry[@"path"];
  if(![self.hiddenPaths containsObject:path])continue;
  BOOL sameProcess=[self.hiddenPids[path]isEqual:entry[@"pid"]];
  if(sameProcess&&(!visible||![visible containsObject:path]))continue;
  NSDate *lastAttempt=self.hiddenSince[path];
  if(lastAttempt&&[now timeIntervalSinceDate:lastAttempt]<5)continue;
  self.hiddenSince[path]=now;[targets addObject:entry];
 }
 // 启动通知负责尽快响应；定时检查补偿启动时序、忙碌和 Dock 重启。
 if(targets.count)[self changeEntries:targets shown:NO completion:nil];
}
- (void)workspaceApplicationDidLaunch:(NSNotification*)n{
 NSRunningApplication *app=n.userInfo[NSWorkspaceApplicationKey];NSString *path=app.bundleURL.path;
 if(!path)return;
 dispatch_async(dispatch_get_main_queue(),^{
  if(![self.hiddenPaths containsObject:path])return;
  [self.hiddenPids removeObjectForKey:path];[self.hiddenSince removeObjectForKey:path];
  [self applyHiddenChoices];
 });
}
- (BOOL)isEntryShown:(NSDictionary*)entry{
 NSString *path=entry[@"path"];
 return self.dockPaths ? [self.dockPaths containsObject:path] : ![self.hiddenPaths containsObject:path];
}
- (void)reload:(id)sender{
 if(self.busy)return;self.dockPaths=VisibleDockPaths();self.filterControl.enabled=YES;if(!self.dockPaths)self.filterControl.selectedSegment=0;NSString *query=self.search.stringValue?:@"";NSMutableArray *filtered=[NSMutableArray array];
 NSArray *all=[self runningEntries];self.allEntries=all;[self reconcileHiddenPaths:all];NSInteger mode=self.filterControl.selectedSegment;
 NSInteger shownCount=0;for(NSDictionary *entry in all){if([self isEntryShown:entry])shownCount++;}
 for(NSDictionary *entry in all){
  BOOL shown=[self isEntryShown:entry];
  if(mode==1&&!shown)continue;
  if(mode==2&&shown)continue;
  if(query.length&&[entry[@"name"]rangeOfString:query options:NSCaseInsensitiveSearch].location==NSNotFound&&[entry[@"bundle"]rangeOfString:query options:NSCaseInsensitiveSearch].location==NSNotFound)continue;
  [filtered addObject:entry];
 }
 self.entries=filtered;[self.table reloadData];
 if(self.operationMessage.length)self.status.stringValue=self.operationMessage;
  else if(self.dockPaths)self.status.stringValue=[NSString stringWithFormat:@"运行中 %lu · 显示中 %ld · 已隐藏 %lu · 已读取原生 Dock 状态",(unsigned long)all.count,(long)shownCount,(unsigned long)(all.count-shownCount)];
  else{NSInteger selectedHidden=0;for(NSDictionary *entry in all)if([self.hiddenPaths containsObject:entry[@"path"]])selectedHidden++;NSString *why=AXIsProcessTrusted()?@"无法读取 Dock 状态（Dock 层级可能已变，稍后自动重试）":@"未读取 Dock 状态（可在系统设置中授权辅助功能）";self.status.stringValue=[NSString stringWithFormat:@"运行中 %lu · 显示选择 %lu · 隐藏选择 %ld · %@",(unsigned long)all.count,(unsigned long)(all.count-selectedHidden),(long)selectedHidden,why];}
 self.restoreButton.enabled=(all.count-shownCount)>0||self.hiddenPaths.count>0;
 [self updateStatusMenuStates];
}
- (void)timerRefresh:(id)sender{
 if(self.busy)return;
 [self applyHiddenChoices];
 if(!self.busy&&self.window.isVisible)[self reload:nil];
}
- (void)searchChanged:(NSNotification*)n{[self reload:nil];}
// 所有会改动 Dock 的操作前统一校验：未授权先弹授权提示并中止，已授权静默继续。
- (BOOL)ensureAccessibility{
 if(AXIsProcessTrusted())return YES;
 [self requestDockAccessibility:nil];
 return NO;
}
- (void)filterChanged:(NSSegmentedControl*)sender{
 if(![self ensureAccessibility]){sender.selectedSegment=0;[self reload:nil];return;}
 [self reload:nil];
}
// 从“系统设置”切回本应用时重新检查权限：已授予就直接刷新，无需重启应用。
- (void)appDidBecomeActive:(NSNotification*)n{
 if(self.busy)return;
 if(!AXIsProcessTrusted()||self.dockPaths)return;
 self.operationMessage=@"已读取到辅助功能权限，状态已刷新。";
 [self reload:nil];
}
// 面板失去焦点自动收起，不再挡着其他窗口；点菜单栏 ▦ →“打开控制面板”可重新唤出。
- (void)appDidResignActive:(NSNotification*)n{
 if(self.busy)return;
 [self.window orderOut:nil];
}
- (NSInteger)numberOfRowsInTableView:(NSTableView*)table{return self.entries.count;}
- (NSTableRowView*)tableView:(NSTableView*)table rowViewForRow:(NSInteger)row{
 NSTableRowView *view=[[NSTableRowView alloc]initWithFrame:NSZeroRect];return view;
}
- (NSView*)tableView:(NSTableView*)table viewForTableColumn:(NSTableColumn*)column row:(NSInteger)row{
 NSDictionary *entry=self.entries[(NSUInteger)row];ApplicationRow *cell=[table makeViewWithIdentifier:@"ApplicationRow" owner:self];if(!cell)cell=[[ApplicationRow alloc]initWithFrame:NSZeroRect];
 NSString *path=entry[@"path"];BOOL shown=self.dockPaths?[self.dockPaths containsObject:path]:![self.hiddenPaths containsObject:path];
 cell.appIcon.image=[NSWorkspace.sharedWorkspace iconForFile:path];cell.nameLabel.stringValue=entry[@"name"];cell.nameLabel.textColor=shown?NSColor.labelColor:NSColor.secondaryLabelColor;
 cell.detailLabel.stringValue=[NSString stringWithFormat:@"%@ · PID %@",shown?@"Dock 中显示":@"Dock 中隐藏",entry[@"pid"]];
 BOOL autoHide=[self.hiddenPaths containsObject:path];
 if(autoHide&&shown)cell.detailLabel.stringValue=[NSString stringWithFormat:@"Dock 中显示 · 等待自动隐藏 · PID %@",entry[@"pid"]];
 if(!self.dockPaths)cell.detailLabel.stringValue=[NSString stringWithFormat:@"%@ · PID %@",shown?@"显示选择":@"隐藏选择（未核验）",entry[@"pid"]];
 cell.toolTip=path;cell.visibilitySwitch.state=shown&&!autoHide?NSControlStateValueOn:NSControlStateValueOff;cell.visibilitySwitch.enabled=!self.busy;
 cell.visibilitySwitch.target=self;cell.visibilitySwitch.action=@selector(toggle:);objc_setAssociatedObject(cell.visibilitySwitch,EntryKey,entry,OBJC_ASSOCIATION_RETAIN_NONATOMIC);return cell;
}
- (void)changeEntries:(NSArray<NSDictionary*>*)entries shown:(BOOL)shown completion:(void(^)(BOOL))completion{
 if(self.busy){if(completion)completion(NO);return;}
 self.busy=YES;self.refreshButton.enabled=NO;self.restoreButton.enabled=NO;[self.table reloadData];[self updateStatusMenuStates];
 self.status.stringValue=shown?@"正在恢复 Dock 图标…":@"正在隐藏 Dock 图标…";
 dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
  NSMutableArray *successful=[NSMutableArray array];NSMutableArray *errors=[NSMutableArray array];NSMutableArray *failed=[NSMutableArray array];
  for(NSDictionary *entry in entries){NSString *error=nil;if(SendRuntimeNotification(entry,shown,&error))[successful addObject:entry];else[errors addObject:error?:@"操作失败。"];}
  NSSet *visible=nil;WaitForDockState(successful,shown,2.5,&visible);

  if(visible){for(NSDictionary *entry in successful){NSRunningApplication *app=[NSRunningApplication runningApplicationWithProcessIdentifier:[entry[@"pid"]intValue]];if(!app||app.terminated)continue;if([visible containsObject:entry[@"path"]]!=shown){[errors addObject:[NSString stringWithFormat:@"%@ 的 Dock 状态未通过核验。",entry[@"name"]]];[failed addObject:entry];}}}
  dispatch_async(dispatch_get_main_queue(),^{
   for(NSDictionary *entry in successful){if([failed containsObject:entry])continue;NSString *p=entry[@"path"];if(shown){[self.hiddenPaths removeObject:p];[self.hiddenSince removeObjectForKey:p];[self.hiddenPids removeObjectForKey:p];}else{[self.hiddenPaths addObject:p];self.hiddenSince[p]=[NSDate date];if(visible)self.hiddenPids[p]=entry[@"pid"];}}
   [self saveChoices];self.busy=NO;self.refreshButton.enabled=YES;
   BOOL ok=errors.count==0&&visible!=nil;
   if(errors.count)self.operationMessage=[errors componentsJoinedByString:@" "];
   else if(!visible)self.operationMessage=@"已发送请求，但未能读取 Dock 实际状态；请稍后刷新确认。";
   else self.operationMessage=shown?@"已恢复：Dock 图标已显示，已取消自动隐藏。":@"已完成：Dock 图标已隐藏，应用重开后会自动再次隐藏。";
   [self reload:nil];if(completion)completion(ok);
  });
 });
}
- (void)toggle:(NSSwitch*)sender{NSDictionary *entry=objc_getAssociatedObject(sender,EntryKey);if(!entry)return;BOOL shown=sender.state==NSControlStateValueOn;
 if(![self ensureAccessibility]){[self reload:nil];return;}
 if(!shown&&![self.acceptedPaths containsObject:entry[@"path"]]){NSAlert*a=[NSAlert new];a.messageText=[NSString stringWithFormat:@"隐藏“%@”的 Dock 图标？",entry[@"name"]];a.informativeText=@"此操作不会修改应用文件或关闭应用。macOS 可能会更新该应用的最小化窗口和桌面空间状态；个别应用的窗口切换行为可能不同。是否继续对这个应用隐藏？";[a addButtonWithTitle:@"隐藏此应用"];[a addButtonWithTitle:@"取消"];NSModalResponse response=[a runModal];if(response!=NSAlertFirstButtonReturn){[self reload:nil];return;}[self.acceptedPaths addObject:entry[@"path"]];[self changeEntries:@[entry] shown:NO completion:nil];return;}
 [self changeEntries:@[entry] shown:shown completion:nil];}
- (void)restoreAll:(id)sender{
 if(self.busy){[self busyNotice:@"全部恢复"];return;}
 if(![self ensureAccessibility]){return;}
 // 以 Dock 实况为准：运行中但 Dock 里没有图标的，都要拉回来。
 // 这样即使本地记录被清空（例如重装后），也不会像以前那样空转。
 NSSet *visible=VisibleDockPaths();
 NSMutableArray *targets=[NSMutableArray array];
 for(NSDictionary *e in[self runningEntries]){
  BOOL shown=visible?[visible containsObject:e[@"path"]]:![self.hiddenPaths containsObject:e[@"path"]];
  if(!shown||[self.hiddenPaths containsObject:e[@"path"]])[targets addObject:e];
 }
 if(targets.count==0){
  [self.hiddenPaths removeAllObjects];[self.hiddenSince removeAllObjects];[self.hiddenPids removeAllObjects];[self saveChoices];
  self.operationMessage=visible?@"已取消全部自动隐藏规则；运行中的应用都已在 Dock 中显示。":@"已取消全部自动隐藏规则；未能读取 Dock 状态，请稍后刷新确认。";
  [self reload:nil];return;
 }
 [self changeEntries:targets shown:YES completion:^(BOOL ok){if(ok){[self.hiddenPaths removeAllObjects];[self.hiddenSince removeAllObjects];[self.hiddenPids removeAllObjects];[self saveChoices];}[self reload:nil];}];
}
- (void)requestDockAccessibility:(id)sender{
  if(AXIsProcessTrusted()){self.operationMessage=@"已允许读取 Dock 状态。";[self reload:nil];return;}
  NSAlert *prompt=[NSAlert new];prompt.messageText=@"需要辅助功能权限";
  prompt.informativeText=@"DockPicker 需要辅助功能权限来读取原生 Dock 图标状态。请在“系统设置 → 隐私与安全性 → 辅助功能”中开启 DockPicker。";
  [prompt addButtonWithTitle:@"打开设置"];[prompt addButtonWithTitle:@"稍后"];
  [self showPanel:nil];NSModalResponse response=[prompt runModal];
  if(response==NSAlertFirstButtonReturn){
    NSDictionary *options=@{(__bridge NSString*)kAXTrustedCheckOptionPrompt:@YES};
    AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
    NSURL *url=[NSURL URLWithString:@"x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"];
    if(url)[NSWorkspace.sharedWorkspace openURL:url];
  }
  self.operationMessage=@"请在系统设置的“隐私与安全性 → 辅助功能”中允许 DockPicker，然后点“刷新”。";
  [self reload:nil];
}
- (void)showPanel:(id)sender{[self.window makeKeyAndOrderFront:nil];[NSApp activate];[NSApp activateIgnoringOtherApps:YES];}
- (BOOL)applicationShouldHandleReopen:(NSApplication*)sender hasVisibleWindows:(BOOL)visible{[self showPanel:nil];return YES;}
- (void)help:(id)sender{
 NSAlert *a=[NSAlert new];a.messageText=@"DockPicker 说明";
 a.informativeText=@"只管理当前运行应用在原生 Dock 中的图标显示；不会修改、重签名或重启应用，也不需要管理员密码。\n\n首次隐藏每个应用前都会单独确认。显示状态可能影响 Dock 的最小化窗口、桌面空间等内部记录；不同应用和未来 macOS 版本的表现可能不同。\n\n点击列表上方的“全部 / 显示中 / 已隐藏”时会检查辅助功能权限，未授权会自动提示开启。该权限只用于核对 Dock 图标状态；未授权时，列表显示的是本工具保存的选择。\n\n菜单栏 ▦ 的下拉列表会列出全部运行中的应用。取消勾选会持续隐藏；重新勾选会显示并取消自动隐藏。列表开关遵循同一规则，文字状态仍以实际 Dock 核验结果为准；每次切换前会校验辅助功能权限。\n\n如果提示“Dock 状态未通过核验”，一般是因为该应用已固定在 Dock 栏。右键点击该应用的 Dock 图标，在“选项”中取消“在程序坞中保留”，然后重试即可。\n\n隐藏选择会长期保存。只要 DockPicker 保持运行，应用重开、Dock 重启或控制面板收起后都会自动补做隐藏；启动瞬间图标仍可能短暂出现。自动处理失败时保留规则并稍后重试，不弹授权框。开启开关会取消该应用的规则；“全部恢复”和“恢复并退出”成功后会清除全部规则，包括未运行应用。直接退出本工具会保持当前隐藏状态，但退出期间无法自动处理新启动的应用，下次启动 DockPicker 后会继续执行规则。";[a runModal];
}
- (void)busyNotice:(NSString*)action{
 self.operationMessage=[NSString stringWithFormat:@"正在处理 Dock 图标变更，请稍后再%@。",action];
 NSAlert *a=[NSAlert new];a.messageText=@"操作正在进行";a.informativeText=self.operationMessage;
 [a addButtonWithTitle:@"好"];[self showPanel:nil];[a runModal];
}
// 退出时把隐藏记录写盘：下次启动仍记得哪些应用被关掉过（不恢复、只记住）。
- (void)applicationWillTerminate:(NSNotification*)n{
 [[NSUserDefaults standardUserDefaults]synchronize];
}
- (void)quit:(id)sender{if(self.busy){[self busyNotice:@"退出"];return;}[self saveChoices];[NSApp terminate:nil];}
- (void)restoreAndQuit:(id)sender{
 if(self.busy){[self busyNotice:@"恢复并退出"];return;}
 NSMutableArray *targets=[NSMutableArray array];for(NSDictionary *e in[self runningEntries])if([self.hiddenPaths containsObject:e[@"path"]])[targets addObject:e];
 if(targets.count==0){[self.hiddenPaths removeAllObjects];[self.hiddenSince removeAllObjects];[self.hiddenPids removeAllObjects];[self saveChoices];[NSApp terminate:nil];return;}
 [self changeEntries:targets shown:YES completion:^(BOOL ok){
  if(ok){[self.hiddenPaths removeAllObjects];[self.hiddenSince removeAllObjects];[self.hiddenPids removeAllObjects];[self saveChoices];[NSApp terminate:nil];return;}
  self.operationMessage=[[NSString stringWithFormat:@"未能恢复全部 Dock 图标，已取消退出。"]stringByAppendingString:self.operationMessage?:@""];
  [self reload:nil];
 }];
}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)sender{return self.busy?NSTerminateCancel:NSTerminateNow;}
- (void)buildMainMenu{
 NSMenu *mainMenu=[NSMenu new];
 NSMenuItem *appMenuItem=[[NSMenuItem alloc]initWithTitle:@"" action:nil keyEquivalent:@""];
 NSMenu *appMenu=[NSMenu new];
 NSMenuItem *quitItem=[[NSMenuItem alloc]initWithTitle:@"退出 DockPicker" action:@selector(quit:) keyEquivalent:@"q"];
 quitItem.target=self;[appMenu addItem:quitItem];appMenuItem.submenu=appMenu;[mainMenu addItem:appMenuItem];
 NSMenuItem *editMenuItem=[[NSMenuItem alloc]initWithTitle:@"" action:nil keyEquivalent:@""];
 NSMenu *editMenu=[NSMenu new];
 for(NSArray *item in @[@[@"撤销",@"undo:",@"z"],@[@"重做",@"redo:",@"Z"],@[@"剪切",@"cut:",@"x"],@[@"复制",@"copy:",@"c"],@[@"粘贴",@"paste:",@"v"],@[@"全选",@"selectAll:",@"a"]]){
  NSMenuItem *i=[[NSMenuItem alloc]initWithTitle:item[0] action:NSSelectorFromString(item[1]) keyEquivalent:item[2]];[editMenu addItem:i];
 }
 editMenuItem.submenu=editMenu;[mainMenu addItem:editMenuItem];
 NSApp.mainMenu=mainMenu;
}
- (void)buildStatusMenu{
 self.statusItem=[NSStatusBar.systemStatusBar statusItemWithLength:NSVariableStatusItemLength];self.statusItem.button.title=@"▦";self.statusItem.button.toolTip=@"DockPicker · 管理原生 Dock 图标显示";
 NSMenu *m=[NSMenu new];m.delegate=self;m.autoenablesItems=NO;self.statusItem.menu=m;
}
- (NSMenuItem*)menuItem:(NSString*)title action:(SEL)action{
 NSMenuItem *i=[[NSMenuItem alloc]initWithTitle:title action:action keyEquivalent:@""];
 i.target=self;i.enabled=action!=NULL;return i;
}
- (void)updateStatusMenuStates{
 for(NSMenuItem *item in self.statusItem.menu.itemArray){
  if(item.action!=@selector(toggleFromMenu:))continue;
  NSDictionary *entry=item.representedObject;
  NSNumber *pending=self.pendingMenuStates[entry[@"path"]];
  BOOL shown=pending?pending.boolValue:(![self.hiddenPaths containsObject:entry[@"path"]]&&[self isEntryShown:entry]);
  item.state=shown?NSControlStateValueOn:NSControlStateValueOff;
  item.enabled=!self.busy;
 }
}
// 菜单每次展开时重建：直接列出全部运行中的应用，勾选状态即当前 Dock 是否显示。
- (void)menuNeedsUpdate:(NSMenu*)menu{
 if(menu!=self.statusItem.menu)return;
 [menu removeAllItems];
 [menu addItem:[self menuItem:@"打开控制面板" action:@selector(showPanel:)]];
 [menu addItem:[self menuItem:@"全部恢复" action:@selector(restoreAll:)]];
 [menu addItem:[self menuItem:@"说明" action:@selector(help:)]];
 [menu addItem:[NSMenuItem separatorItem]];
 NSArray *rows=[self runningEntries];
 self.dockPaths=VisibleDockPaths();
 if(rows.count==0)[menu addItem:[self menuItem:@"没有可管理的运行中应用" action:nil]];
 for(NSDictionary *entry in rows){
  NSMenuItem *i=[self menuItem:entry[@"name"] action:@selector(toggleFromMenu:)];
  i.representedObject=entry;i.toolTip=entry[@"path"];
  [menu addItem:i];
 }
 [self updateStatusMenuStates];
 [menu addItem:[NSMenuItem separatorItem]];
 [menu addItem:[self menuItem:@"恢复并退出" action:@selector(restoreAndQuit:)]];
 [menu addItem:[self menuItem:@"退出" action:@selector(quit:)]];
}
// 点击立即反转勾选并执行 Dock 操作；完成后以核验结果同步，失败时显示原因。
- (void)toggleFromMenu:(NSMenuItem*)item{
 NSDictionary *entry=item.representedObject;if(!entry)return;
 if(self.busy){[self busyNotice:@"切换 Dock 图标"];return;}
 if(![self ensureAccessibility])return;
 BOOL shown=item.state!=NSControlStateValueOn;
 self.pendingMenuStates=@{entry[@"path"]:@(shown)};
 [self changeEntries:@[entry] shown:shown completion:^(BOOL ok){
  self.pendingMenuStates=nil;
  [self updateStatusMenuStates];
  if(!ok)[self showPanel:nil];
 }];
}
- (void)buildWindow{
 self.window=[[NSWindow alloc]initWithContentRect:NSMakeRect(0,0,660,570) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable backing:NSBackingStoreBuffered defer:NO];self.window.title=@"DockPicker — 管理应用在原生 Dock 的显示";self.window.releasedWhenClosed=NO;self.window.minSize=NSMakeSize(700,380);[self.window center];NSView*c=self.window.contentView;
 NSTextField *title=[NSTextField labelWithString:@"选择应用在原生 Dock 中的显示"];title.font=[NSFont systemFontOfSize:18 weight:NSFontWeightSemibold];
 NSTextField *subtitle=[NSTextField labelWithString:@"DockPicker 1.0.2 Preview 1 · 直接控制原生 Dock，不改应用文件"];subtitle.font=[NSFont systemFontOfSize:11];subtitle.textColor=NSColor.secondaryLabelColor;
 self.search=[NSSearchField new];self.search.placeholderString=@"搜索运行中的应用";
  self.filterControl=[NSSegmentedControl segmentedControlWithLabels:@[@"全部",@"显示中",@"已隐藏"] trackingMode:NSSegmentSwitchTrackingSelectOne target:self action:@selector(filterChanged:)];self.filterControl.selectedSegment=0;self.filterControl.toolTip=@"筛选当前运行中的应用";
 self.refreshButton=[NSButton buttonWithTitle:@"刷新" target:self action:@selector(reload:)];self.restoreButton=[NSButton buttonWithTitle:@"全部恢复" target:self action:@selector(restoreAll:)];
 NSButton *help=[NSButton buttonWithTitle:@"说明" target:self action:@selector(help:)];
 self.table=[NSTableView new];NSTableColumn*col=[[NSTableColumn alloc]initWithIdentifier:@"Application"];col.resizingMask=NSTableColumnAutoresizingMask;[self.table addTableColumn:col];self.table.columnAutoresizingStyle=NSTableViewUniformColumnAutoresizingStyle;self.table.headerView=nil;self.table.rowHeight=46;self.table.intercellSpacing=NSMakeSize(0,2);self.table.selectionHighlightStyle=NSTableViewSelectionHighlightStyleNone;self.table.style=NSTableViewStyleInset;self.table.delegate=self;self.table.dataSource=self;
 NSScrollView *scroll=[NSScrollView new];scroll.documentView=self.table;scroll.hasVerticalScroller=YES;scroll.borderType=NSBezelBorder;
 self.status=[NSTextField labelWithString:@""];self.status.font=[NSFont systemFontOfSize:11];self.status.textColor=NSColor.secondaryLabelColor;self.status.maximumNumberOfLines=4;self.status.lineBreakMode=NSLineBreakByWordWrapping;
 for(NSView*v in @[title,subtitle,self.search,self.filterControl,self.refreshButton,self.restoreButton,help,scroll,self.status]){v.translatesAutoresizingMaskIntoConstraints=NO;[c addSubview:v];}
 [NSLayoutConstraint activateConstraints:@[
 [title.topAnchor constraintEqualToAnchor:c.topAnchor constant:18],[title.leadingAnchor constraintEqualToAnchor:c.leadingAnchor constant:18],
 [subtitle.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:5],[subtitle.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],[subtitle.trailingAnchor constraintLessThanOrEqualToAnchor:c.trailingAnchor constant:-18],
 [self.search.topAnchor constraintEqualToAnchor:subtitle.bottomAnchor constant:16],[self.search.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],[self.search.widthAnchor constraintEqualToConstant:190],
 [self.filterControl.leadingAnchor constraintEqualToAnchor:self.search.trailingAnchor constant:10],[self.filterControl.centerYAnchor constraintEqualToAnchor:self.search.centerYAnchor],[self.filterControl.widthAnchor constraintEqualToConstant:190],
  [self.refreshButton.leadingAnchor constraintEqualToAnchor:self.filterControl.trailingAnchor constant:10],[self.refreshButton.centerYAnchor constraintEqualToAnchor:self.search.centerYAnchor],
 [self.restoreButton.leadingAnchor constraintEqualToAnchor:self.refreshButton.trailingAnchor constant:8],[self.restoreButton.centerYAnchor constraintEqualToAnchor:self.search.centerYAnchor],
 [help.leadingAnchor constraintEqualToAnchor:self.restoreButton.trailingAnchor constant:8],[help.trailingAnchor constraintEqualToAnchor:c.trailingAnchor constant:-18],[help.centerYAnchor constraintEqualToAnchor:self.search.centerYAnchor],
 [scroll.topAnchor constraintEqualToAnchor:self.search.bottomAnchor constant:12],[scroll.leadingAnchor constraintEqualToAnchor:c.leadingAnchor constant:12],[scroll.trailingAnchor constraintEqualToAnchor:c.trailingAnchor constant:-12],
 [self.status.topAnchor constraintEqualToAnchor:scroll.bottomAnchor constant:10],[self.status.leadingAnchor constraintEqualToAnchor:c.leadingAnchor constant:18],[self.status.trailingAnchor constraintEqualToAnchor:c.trailingAnchor constant:-18],[self.status.heightAnchor constraintGreaterThanOrEqualToConstant:46],[self.status.bottomAnchor constraintEqualToAnchor:c.bottomAnchor constant:-12]
 ]];
}
@end
int main(void){@autoreleasepool{
 NSApplication*app=NSApplication.sharedApplication;[app setActivationPolicy:NSApplicationActivationPolicyAccessory];AppDelegate*d=[AppDelegate new];app.delegate=d;[app run];
}}
