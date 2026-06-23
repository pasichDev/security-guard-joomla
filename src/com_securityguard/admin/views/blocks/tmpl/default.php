<?php
defined('_JEXEC') or die;
$now = time();
?>

<form action="<?php echo JRoute::_('index.php?option=com_securityguard&view=blocks'); ?>" method="post" name="adminForm" id="adminForm">

<div id="j-sidebar-container" class="span2">
    <?php echo $this->sidebar; ?>
</div>

<div id="j-main-container" class="span10">

    <table class="table table-striped table-hover">
        <thead>
            <tr>
                <th><?php echo JText::_('COM_SECURITYGUARD_IP'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_REASON'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_ATTEMPTS'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_BLOCKED_UNTIL'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_LAST_URL'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_ACTION'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($this->items)): ?>
                <tr><td colspan="6" class="text-center"><?php echo JText::_('COM_SECURITYGUARD_NO_BLOCKS'); ?></td></tr>
            <?php else: ?>
                <?php foreach ($this->items as $item): ?>
                <?php $active = $item->blocked_until > $now; ?>
                <tr class="<?php echo $active ? 'sg-active' : 'sg-expired'; ?>">
                    <td><code><?php echo htmlspecialchars($item->ip); ?></code></td>
                    <td><span class="badge"><?php echo htmlspecialchars($item->reason); ?></span></td>
                    <td><?php echo (int)$item->attempts; ?></td>
                    <td>
                        <?php if ($active): ?>
                            <span class="label label-important">
                                <?php echo date('Y-m-d H:i', $item->blocked_until); ?>
                            </span>
                            <small>(<?php echo gmdate('H:i:s', $item->blocked_until - $now); ?> <?php echo JText::_('COM_SECURITYGUARD_REMAINING'); ?>)</small>
                        <?php else: ?>
                            <span class="label"><?php echo JText::_('COM_SECURITYGUARD_EXPIRED'); ?></span>
                        <?php endif; ?>
                    </td>
                    <td><small><?php echo htmlspecialchars(substr($item->last_url ?? '', 0, 80)); ?></small></td>
                    <td>
                        <button type="button"
                                class="btn btn-small btn-warning sg-unblock-btn"
                                data-ip="<?php echo htmlspecialchars($item->ip, ENT_QUOTES, 'UTF-8'); ?>">
                            <?php echo JText::_('COM_SECURITYGUARD_UNBLOCK'); ?>
                        </button>
                    </td>
                </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>

    <?php echo $this->pagination->getListFooter(); ?>

    <input type="hidden" name="task" value="" />
    <input type="hidden" name="boxchecked" value="0" />
    <input type="hidden" name="ip" id="sg-unblock-ip" value="" />
    <?php echo JHtml::_('form.token'); ?>
</div>
</form>

<script>
(function () {
    var form = document.getElementById('adminForm');
    var ipField = document.getElementById('sg-unblock-ip');
    if (!form || !ipField) { return; }
    form.addEventListener('click', function (e) {
        var btn = e.target.closest ? e.target.closest('.sg-unblock-btn') : null;
        if (!btn) { return; }
        var ip = btn.getAttribute('data-ip') || '';
        if (window.confirm('Unblock ' + ip + '?')) {
            ipField.value = ip;
            Joomla.submitform('unblock', form);
        }
    });
})();
</script>
