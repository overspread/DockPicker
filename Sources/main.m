#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <Security/AuthSession.h>
#import <ApplicationServices/ApplicationServices.h>
#import <objc/runtime.h>

// DockPicker runtime-only build. No target bundle writes, signing, chown,
// privilege escalation, injection, replacement Dock, or overlay windows.
// The internal LaunchServices type-change notification is intentionally kept
// separate from the application's real activation policy. This is experimental
// system integration: the Dock also updates internal window/Spaces bookkeeping.

static NSString *const HiddenPathsKey=@"runtime.hiddenApplicationPaths.v2";
static const void *EntryKey=&EntryKey;
static id AXValue(AXUIElementRef e,CFStringRef k){CFTypeRef v=NULL;return AXUIElementCopyAttributeValue(e,k,&v)==kAXErrorSuccess?CFBridgingRelease(v):nil;}
static void CollectDockPaths(AXUIElementRef e,int depth,NSMutableSet *paths){
 if(depth>4)return;
 if([AXValue(e,kAXSubroleAttribute)isEqualToString:@"AXApplicationDockItem"]){id u=AXValue(e,kAXURLAttribute);if([u isKindOfClass:[NSURL class]])[paths addObject:[u path]];}
 for(id child in (NSArray*)AXValue(e,kAXChildrenAttribute))CollectDockPaths((__bridge AXUIElementRef)child,depth+1,paths);
}
static NSSet *VisibleDockPaths(void){
 if(!AXIsProcessTrusted())return nil;
 NSMutableSet *paths=[NSMutableSet set];
 for(NSRunningApplication *a in [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.dock"]){AXUIElementRef e=AXUIElementCreateApplication(a.processIdentifier);CollectDockPaths(e,0,paths);CFRelease(e);}
 return paths;
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
 NSPipe *pipe=[NSPipe pipe];task.standardOutput=pipe;task.standardError=pipe;
 NSError *launchError=nil;if(![task launchAndReturnError:&launchError]){if(error)*error=launchError.localizedDescription;return NO;}
 NSData *output=[pipe.fileHandleForReading readDataToEndOfFile];[task waitUntilExit];
 if(task.terminationStatus!=0){if(error)*error=[[NSString alloc]initWithData:output encoding:NSUTF8StringEncoding]?:@"通知发送失败。";return NO;}
 return YES;
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
 _visibilitySwitch=[NSSwitch new];_visibilitySwitch.toolTip=@"打开：在原生 Dock 显示；关闭：请求从原生 Dock 隐藏。";
 for(NSView *v in @[_appIcon,_nameLabel,_detailLabel,_visibilitySwitch]){v.translatesAutoresizingMaskIntoConstraints=NO;[self addSubview:v];}
 [NSLayoutConstraint activateConstraints:@[
  [_appIcon.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:10],[_appIcon.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],[_appIcon.widthAnchor constraintEqualToConstant:28],[_appIcon.heightAnchor constraintEqualToConstant:28],
  [_nameLabel.leadingAnchor constraintEqualToAnchor:_appIcon.trailingAnchor constant:11],[_nameLabel.topAnchor constraintEqualToAnchor:self.topAnchor constant:7],[_nameLabel.trailingAnchor constraintLessThanOrEqualToAnchor:_visibilitySwitch.leadingAnchor constant:-14],
  [_detailLabel.leadingAnchor constraintEqualToAnchor:_nameLabel.leadingAnchor],[_detailLabel.topAnchor constraintEqualToAnchor:_nameLabel.bottomAnchor constant:2],[_detailLabel.trailingAnchor constraintLessThanOrEqualToAnchor:_visibilitySwitch.leadingAnchor constant:-14],
  [_visibilitySwitch.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-12],[_visibilitySwitch.centerYAnchor constraintEqualToAnchor:self.centerYAnchor]
 ]];
 }return self;}
@end

@interface AppDelegate:NSObject<NSApplicationDelegate,NSTableViewDataSource,NSTableViewDelegate,NSSearchFieldDelegate>
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
@property(strong) NSSet<NSString*> *dockPaths;
@property BOOL busy;
@property BOOL allowQuit;
@property BOOL quitting;
@property(strong) NSMutableSet<NSString*> *acceptedPaths;
@property(copy) NSString *operationMessage;
@end
@implementation AppDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)n{
 self.hiddenPaths=[NSMutableSet setWithArray:[[NSUserDefaults standardUserDefaults]arrayForKey:HiddenPathsKey]?:@[]];self.acceptedPaths=[NSMutableSet set];
 self.entries=@[];[self buildWindow];[self buildStatusMenu];[self reload:nil];[self showPanel:nil];
 [[NSNotificationCenter defaultCenter]addObserver:self selector:@selector(searchChanged:) name:NSControlTextDidChangeNotification object:self.search];
 [NSTimer scheduledTimerWithTimeInterval:3 target:self selector:@selector(timerRefresh:) userInfo:nil repeats:YES];
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
- (void)saveChoices{[[NSUserDefaults standardUserDefaults]setObject:self.hiddenPaths.allObjects forKey:HiddenPathsKey];}
- (BOOL)isEntryShown:(NSDictionary*)entry{
 NSString *path=entry[@"path"];
 return self.dockPaths ? [self.dockPaths containsObject:path] : ![self.hiddenPaths containsObject:path];
}
- (void)reload:(id)sender{
 if(self.busy)return;self.dockPaths=VisibleDockPaths();self.filterControl.enabled=(self.dockPaths!=nil);if(!self.dockPaths)self.filterControl.selectedSegment=0;NSString *query=self.search.stringValue?:@"";NSMutableArray *filtered=[NSMutableArray array];
 NSArray *all=[self runningEntries];self.allEntries=all;NSInteger mode=self.filterControl.selectedSegment;
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
  else{NSInteger selectedHidden=0;for(NSDictionary *entry in all)if([self.hiddenPaths containsObject:entry[@"path"]])selectedHidden++;self.status.stringValue=[NSString stringWithFormat:@"运行中 %lu · 显示选择 %lu · 隐藏选择 %ld · 尚未读取 Dock 实际状态（可授权辅助功能）",(unsigned long)all.count,(unsigned long)(all.count-selectedHidden),(long)selectedHidden];}
 self.restoreButton.enabled=self.hiddenPaths.count>0;
}
- (void)timerRefresh:(id)sender{if(!self.busy)[self reload:nil];}
- (void)searchChanged:(NSNotification*)n{[self reload:nil];}
- (void)filterChanged:(NSSegmentedControl*)sender{[self reload:nil];}
- (NSInteger)numberOfRowsInTableView:(NSTableView*)table{return self.entries.count;}
- (NSTableRowView*)tableView:(NSTableView*)table rowViewForRow:(NSInteger)row{
 NSTableRowView *view=[[NSTableRowView alloc]initWithFrame:NSZeroRect];return view;
}
- (NSView*)tableView:(NSTableView*)table viewForTableColumn:(NSTableColumn*)column row:(NSInteger)row{
 NSDictionary *entry=self.entries[(NSUInteger)row];ApplicationRow *cell=[table makeViewWithIdentifier:@"ApplicationRow" owner:self];if(!cell)cell=[[ApplicationRow alloc]initWithFrame:NSZeroRect];
 NSString *path=entry[@"path"];BOOL shown=self.dockPaths?[self.dockPaths containsObject:path]:![self.hiddenPaths containsObject:path];
 cell.appIcon.image=[NSWorkspace.sharedWorkspace iconForFile:path];cell.nameLabel.stringValue=entry[@"name"];cell.nameLabel.textColor=shown?NSColor.labelColor:NSColor.secondaryLabelColor;
 cell.detailLabel.stringValue=[NSString stringWithFormat:@"%@ · PID %@",shown?@"原生 Dock 显示":@"原生 Dock 隐藏",entry[@"pid"]];
 if(!self.dockPaths)cell.detailLabel.stringValue=[NSString stringWithFormat:@"%@ · PID %@",shown?@"显示选择":@"隐藏选择（未读取 Dock）",entry[@"pid"]];
 cell.toolTip=path;cell.visibilitySwitch.state=shown?NSControlStateValueOn:NSControlStateValueOff;cell.visibilitySwitch.enabled=!self.busy;
 cell.visibilitySwitch.target=self;cell.visibilitySwitch.action=@selector(toggle:);objc_setAssociatedObject(cell.visibilitySwitch,EntryKey,entry,OBJC_ASSOCIATION_RETAIN_NONATOMIC);return cell;
}
- (void)changeEntries:(NSArray<NSDictionary*>*)entries shown:(BOOL)shown completion:(void(^)(BOOL))completion{
 if(self.busy){if(completion)completion(NO);return;}
 self.busy=YES;self.refreshButton.enabled=NO;self.restoreButton.enabled=NO;[self.table reloadData];
 self.status.stringValue=shown?@"正在恢复原生 Dock 图标…":@"正在请求隐藏原生 Dock 图标…";
 dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
  NSMutableArray *successful=[NSMutableArray array];NSMutableArray *errors=[NSMutableArray array];
  for(NSDictionary *entry in entries){NSString *error=nil;if(SendRuntimeNotification(entry,shown,&error))[successful addObject:entry];else[errors addObject:error?:@"操作失败。"];} 
  [NSThread sleepForTimeInterval:.8];
  NSSet *visible=VisibleDockPaths();
  if(visible){for(NSDictionary *entry in successful){NSRunningApplication *app=[NSRunningApplication runningApplicationWithProcessIdentifier:[entry[@"pid"]intValue]];if(!app||app.terminated)continue;if([visible containsObject:entry[@"path"]]!=shown)[errors addObject:[NSString stringWithFormat:@"%@ 的 Dock 状态未通过核验。",entry[@"name"]]];}}
  dispatch_async(dispatch_get_main_queue(),^{
   for(NSDictionary *entry in successful){if(shown)[self.hiddenPaths removeObject:entry[@"path"]];else[self.hiddenPaths addObject:entry[@"path"]];}
   [self saveChoices];self.busy=NO;self.refreshButton.enabled=YES;
   BOOL ok=errors.count==0;
   self.operationMessage=ok?(visible?(shown?@"已核验：原生 Dock 图标已恢复。":@"已核验：原生 Dock 图标已隐藏。"):@"通知已发送，但未核验 Dock 状态；可在辅助功能中允许 DockPicker 读取。"):[errors componentsJoinedByString:@" "];
   [self reload:nil];if(completion)completion(ok);
  });
 });
}
- (void)toggle:(NSSwitch*)sender{NSDictionary *entry=objc_getAssociatedObject(sender,EntryKey);if(!entry)return;BOOL shown=sender.state==NSControlStateValueOn;
 if(!shown&&![self.acceptedPaths containsObject:entry[@"path"]]){NSAlert*a=[NSAlert new];a.messageText=[NSString stringWithFormat:@"在原生 Dock 隐藏“%@”？",entry[@"name"]];a.informativeText=@"这会通过未公开的 macOS 运行时通知隐藏图标，不修改或重启应用。Dock 仍会执行内部退出清理，可能影响该应用的最小化窗口、Spaces 或 App Exposé。该应用已在本机测试程序以外未经完整验证；是否只对这个应用继续？";[a addButtonWithTitle:@"继续此应用试验"];[a addButtonWithTitle:@"取消"];[self showPanel:nil];[a beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response){if(response!=NSAlertFirstButtonReturn){[self reload:nil];return;}[self.acceptedPaths addObject:entry[@"path"]];[self changeEntries:@[entry] shown:NO completion:nil];}];return;}
 [self changeEntries:@[entry] shown:shown completion:nil];}
- (void)restoreAll:(id)sender{
 NSMutableArray *targets=[NSMutableArray array];for(NSDictionary *e in[self runningEntries])if([self.hiddenPaths containsObject:e[@"path"]])[targets addObject:e];
 if(targets.count==0){[self.hiddenPaths removeAllObjects];[self saveChoices];[self reload:nil];return;}
 [self changeEntries:targets shown:YES completion:^(BOOL ok){if(ok){[self.hiddenPaths removeAllObjects];[self saveChoices];[self reload:nil];}}];
}
- (void)requestDockAccessibility:(id)sender{
 if(AXIsProcessTrusted()){self.operationMessage=@"已允许读取原生 Dock 状态。";[self reload:nil];return;}
 NSDictionary *options=@{(__bridge NSString*)kAXTrustedCheckOptionPrompt:@YES};
 AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
 NSURL *url=[NSURL URLWithString:@"x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"];
 if(url)[NSWorkspace.sharedWorkspace openURL:url];
 self.operationMessage=@"请在系统设置的“隐私与安全性 → 辅助功能”中允许 DockPicker；授权后重新打开本工具，再核验图标状态。";
 [self reload:nil];
}
- (void)showPanel:(id)sender{[self.window makeKeyAndOrderFront:nil];[NSApp activate];[NSApp activateIgnoringOtherApps:YES];}
- (BOOL)applicationShouldHandleReopen:(NSApplication*)sender hasVisibleWindows:(BOOL)visible{[self showPanel:nil];return YES;}
- (void)help:(id)sender{
 NSAlert *a=[NSAlert new];a.messageText=@"DockPicker 1.0 说明";
 a.informativeText=@"只控制当前运行应用在原生 Dock 中的显示；不修改、重签名或重启目标应用，不需要管理员密码。\n\n首次隐藏每个应用前会询问确认。你已在当前设备实际测试并反馈通知未影响使用；不同应用、最小化窗口/Spaces及未来 macOS 版本仍可能有差异。\n\n菜单栏 ▦ →“授权读取 Dock 状态”可打开辅助功能设置。该权限只用于核验原生 Dock 图标；未授权时，底部会明确显示尚未读取实际状态，列表仅显示本工具的保存选择。\n\n目标应用或 Dock 重启后图标可能重新出现；“全部恢复”会重新请求显示。退出本工具时会尝试恢复仍运行的已隐藏应用。";[a runModal];
}
- (void)quit:(id)sender{[NSApp terminate:nil];}
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)sender{
 if(self.allowQuit||self.hiddenPaths.count==0)return NSTerminateNow;
 if(self.busy)return NSTerminateCancel;
 NSMutableArray *targets=[NSMutableArray array];for(NSDictionary *e in[self runningEntries])if([self.hiddenPaths containsObject:e[@"path"]])[targets addObject:e];
 if(targets.count==0){[self.hiddenPaths removeAllObjects];[self saveChoices];return NSTerminateNow;}
 self.quitting=YES;[self changeEntries:targets shown:YES completion:^(BOOL ok){if(ok){[self.hiddenPaths removeAllObjects];[self saveChoices];self.allowQuit=YES;}self.quitting=NO;[NSApp replyToApplicationShouldTerminate:ok];}];return NSTerminateLater;
}
- (void)buildStatusMenu{
 self.statusItem=[NSStatusBar.systemStatusBar statusItemWithLength:NSVariableStatusItemLength];self.statusItem.button.title=@"▦";self.statusItem.button.toolTip=@"DockPicker · 原生 Dock 运行时控制";
 NSMenu *m=[NSMenu new];for(NSArray *item in @[@[@"打开控制面板",NSStringFromSelector(@selector(showPanel:))],@[@"授权读取 Dock 状态",NSStringFromSelector(@selector(requestDockAccessibility:))],@[@"全部恢复",NSStringFromSelector(@selector(restoreAll:))],@[@"说明",NSStringFromSelector(@selector(help:))],@[@"恢复并退出",NSStringFromSelector(@selector(quit:))]]){NSMenuItem *i=[[NSMenuItem alloc]initWithTitle:item[0] action:NSSelectorFromString(item[1]) keyEquivalent:@""];i.target=self;[m addItem:i];}self.statusItem.menu=m;
}
- (void)buildWindow{
 self.window=[[NSWindow alloc]initWithContentRect:NSMakeRect(0,0,660,570) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskResizable backing:NSBackingStoreBuffered defer:NO];self.window.title=@"DockPicker — 原生 Dock 图标控制";self.window.releasedWhenClosed=NO;self.window.minSize=NSMakeSize(560,380);[self.window center];NSView*c=self.window.contentView;
 NSTextField *title=[NSTextField labelWithString:@"选择应用在原生 Dock 中的显示"];title.font=[NSFont systemFontOfSize:18 weight:NSFontWeightSemibold];
 NSTextField *subtitle=[NSTextField labelWithString:@"DockPicker 1.0 · 直接控制原生 Dock，不改应用文件"];subtitle.font=[NSFont systemFontOfSize:11];subtitle.textColor=NSColor.secondaryLabelColor;
 self.search=[NSSearchField new];self.search.placeholderString=@"搜索运行中的应用";
  self.filterControl=[NSSegmentedControl segmentedControlWithLabels:@[@"全部",@"显示中",@"已隐藏"] trackingMode:NSSegmentSwitchTrackingSelectOne target:self action:@selector(filterChanged:)];self.filterControl.selectedSegment=0;self.filterControl.toolTip=@"筛选当前运行中的应用";
 self.refreshButton=[NSButton buttonWithTitle:@"刷新" target:self action:@selector(reload:)];self.restoreButton=[NSButton buttonWithTitle:@"全部恢复" target:self action:@selector(restoreAll:)];
 NSButton *help=[NSButton buttonWithTitle:@"说明" target:self action:@selector(help:)];
 self.table=[NSTableView new];NSTableColumn*col=[[NSTableColumn alloc]initWithIdentifier:@"Application"];col.resizingMask=NSTableColumnAutoresizingMask;[self.table addTableColumn:col];self.table.columnAutoresizingStyle=NSTableViewUniformColumnAutoresizingStyle;self.table.headerView=nil;self.table.rowHeight=46;self.table.intercellSpacing=NSMakeSize(0,2);self.table.selectionHighlightStyle=NSTableViewSelectionHighlightStyleNone;self.table.style=NSTableViewStyleInset;self.table.delegate=self;self.table.dataSource=self;
 NSScrollView *scroll=[NSScrollView new];scroll.documentView=self.table;scroll.hasVerticalScroller=YES;scroll.borderType=NSBezelBorder;
 self.status=[NSTextField labelWithString:@""];self.status.font=[NSFont systemFontOfSize:11];self.status.textColor=NSColor.secondaryLabelColor;self.status.maximumNumberOfLines=2;self.status.lineBreakMode=NSLineBreakByWordWrapping;
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
 [self.status.topAnchor constraintEqualToAnchor:scroll.bottomAnchor constant:10],[self.status.leadingAnchor constraintEqualToAnchor:c.leadingAnchor constant:18],[self.status.trailingAnchor constraintEqualToAnchor:c.trailingAnchor constant:-18],[self.status.heightAnchor constraintGreaterThanOrEqualToConstant:28],[self.status.bottomAnchor constraintEqualToAnchor:c.bottomAnchor constant:-12]
 ]];
}
@end
int main(void){@autoreleasepool{
 NSApplication*app=NSApplication.sharedApplication;[app setActivationPolicy:NSApplicationActivationPolicyAccessory];AppDelegate*d=[AppDelegate new];app.delegate=d;[app run];
}}
