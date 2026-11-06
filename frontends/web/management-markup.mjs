export const managementMarkup = `<span id="connection-state"></span>

<form id="connect-form">
<label><span data-i18n="web.agentAddress">Agent 地址</span><input id="agent-origin" type="url" value="http://127.0.0.1:8445" required></label>
<label><span data-i18n="web.pairingSecret">配对秘密</span><input id="pair-secret" type="password" autocomplete="off" required></label>
<button id="connect" type="submit" data-i18n="common.connect">连接</button>
<button id="disconnect" type="button" disabled data-i18n="common.disconnect">断开</button>
<button id="forget" type="button" disabled data-i18n="web.changeAgent">更换 Agent</button>
</form>
<p id="notice" role="status" aria-live="polite">输入 Agent 地址与配对秘密。</p>
<fieldset id="workspace" disabled>
<section>
<div class="section-heading"><h2 data-i18n="web.system">系统</h2><button id="refresh-systems" type="button" data-i18n="common.refresh">刷新</button></div>
<label><span data-i18n="web.system">系统</span><select id="systems"><option value="">暂无系统</option></select></label>
<dl><dt data-i18n="common.name">名称</dt><dd id="system-name">—</dd><dt data-i18n="web.powerState">电源状态</dt><dd id="power-state">—</dd></dl>
<p id="boot-state">尚未读取启动设置</p>
<form id="boot-form"><label><span data-i18n="web.bootTarget">下一次启动</span><select id="boot-target" disabled></select></label><label><span data-i18n="web.bootMode">启动模式</span><select id="boot-mode" disabled><option value="preserve" data-i18n="web.bootPreserve">保持现有模式</option></select></label><button id="apply-boot" type="submit" disabled data-i18n="common.set">设置</button></form>
<form id="power-form"><label><span data-i18n="power.actions">电源操作</span><select id="power-actions" disabled><option value="" data-i18n="power.noActions">无可用操作</option></select></label><button id="apply-power" type="submit" disabled data-i18n="power.execute">执行</button></form>
</section>
<section>
<div class="section-heading"><h2 data-i18n="sensor.title">传感器</h2><button id="refresh-sensors" type="button" disabled data-i18n="common.refresh">刷新</button></div>
<p id="sensors-state">尚未读取</p>
<div class="table-scroll"><table><thead><tr><th data-i18n="sensor.name">名称</th><th data-i18n="sensor.reading">读数</th><th data-i18n="sensor.units">单位</th><th data-i18n="sensor.health">健康</th><th data-i18n="sensor.state">状态</th></tr></thead><tbody id="sensors"></tbody></table></div>
</section>
<section>
<div class="section-heading"><h2 data-i18n="task.title">任务</h2><button id="refresh-tasks" type="button" disabled data-i18n="common.refresh">刷新</button></div>
<p id="tasks-state">尚未读取</p>
<div class="table-scroll"><table><thead><tr><th data-i18n="task.task">任务</th><th data-i18n="task.state">状态</th><th data-i18n="task.result">结果</th><th data-i18n="task.progress">进度</th></tr></thead><tbody id="tasks"></tbody></table></div>
</section>
<section>
<div class="section-heading"><h2 data-i18n="media.title">虚拟媒体</h2><button id="refresh-media" type="button" disabled data-i18n="common.refresh">刷新</button></div>
<label><span data-i18n="media.title">虚拟媒体</span><select id="media-devices" disabled></select></label>
<p id="media-state" role="status"></p>
<form id="media-form"><label><span data-i18n="media.imageUrl">镜像 URL（设备可访问）</span><input id="media-image-url" type="url" required></label><button id="mount-media" type="submit" disabled data-i18n="media.mount">挂载</button><button id="eject-media" type="button" disabled data-i18n="media.eject">弹出</button></form>
<form id="media-local-form"><label><span data-i18n="media.file">文件</span><input id="media-file" type="file" required disabled></label><button id="mount-local-media" type="submit" disabled data-i18n="media.mount">挂载</button></form>
</section>
</fieldset>
<dialog id="power-confirm"><form method="dialog"><h2 data-i18n="web.confirmTitle">确认操作</h2><p id="confirm-message"></p><div class="dialog-actions"><button value="cancel" data-i18n="common.cancel">取消</button><button value="confirm" data-i18n="web.confirmExecute">确认执行</button></div></form></dialog>`;
