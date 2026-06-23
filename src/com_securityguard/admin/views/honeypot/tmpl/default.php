<?php defined('_JEXEC') or die; ?>
<form action="<?php echo JRoute::_('index.php?option=com_securityguard&view=honeypot'); ?>" method="post" name="adminForm" id="adminForm">
<div id="j-sidebar-container" class="span2"><?php echo $this->sidebar; ?></div>
<div id="j-main-container" class="span10">

    <div class="alert alert-info">
        <strong><?php echo JText::_('COM_SECURITYGUARD_HONEYPOT_INFO_TITLE'); ?>:</strong>
        <?php echo JText::_('COM_SECURITYGUARD_HONEYPOT_INFO'); ?>
    </div>

    <table class="table table-striped table-hover">
        <thead>
            <tr>
                <th><?php echo JText::_('COM_SECURITYGUARD_TIMESTAMP'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_IP'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_TRAP_URL'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_USER_AGENT'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($this->items)): ?>
                <tr><td colspan="4" class="text-center sg-empty"><?php echo JText::_('COM_SECURITYGUARD_NO_HONEYPOT_HITS'); ?></td></tr>
            <?php else: ?>
                <?php foreach ($this->items as $item): ?>
                <tr>
                    <td><small><?php echo htmlspecialchars($item->hit_at); ?></small></td>
                    <td><code><?php echo htmlspecialchars($item->ip); ?></code></td>
                    <td><span class="badge badge-warning"><?php echo htmlspecialchars(substr($item->url, 0, 100)); ?></span></td>
                    <td><small><?php echo htmlspecialchars(substr($item->user_agent ?? '', 0, 80)); ?></small></td>
                </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>

    <?php echo $this->pagination->getListFooter(); ?>
    <input type="hidden" name="task" value="" />
    <?php echo JHtml::_('form.token'); ?>
</div>
</form>
