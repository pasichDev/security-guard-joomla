<?php defined('_JEXEC') or die; ?>
<form action="<?php echo JRoute::_('index.php?option=com_securityguard&view=scores'); ?>" method="post" name="adminForm" id="adminForm">
<div id="j-sidebar-container" class="span2"><?php echo $this->sidebar; ?></div>
<div id="j-main-container" class="span10">

    <div class="alert alert-info">
        <strong><?php echo JText::_('COM_SECURITYGUARD_SCORES_INFO_TITLE'); ?>:</strong>
        <?php echo JText::sprintf('COM_SECURITYGUARD_SCORES_INFO', $this->threshold); ?>
    </div>

    <table class="table table-striped table-hover">
        <thead>
            <tr>
                <th><?php echo JText::_('COM_SECURITYGUARD_IP'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_SCORE'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_PROGRESS'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_EVENTS'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_LAST_ACTIVITY'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($this->items)): ?>
                <tr><td colspan="5" class="text-center sg-empty"><?php echo JText::_('COM_SECURITYGUARD_NO_SCORES'); ?></td></tr>
            <?php else: ?>
                <?php foreach ($this->items as $item): ?>
                <?php
                    $pct = min(100, round((int)$item->score / max(1, $this->threshold) * 100));
                    $events = !empty($item->events) ? json_decode($item->events, true) : [];
                    if (!is_array($events)) $events = [];
                    $uniqueEvents = array_count_values($events);
                ?>
                <tr>
                    <td><code><?php echo htmlspecialchars($item->ip); ?></code></td>
                    <td><strong style="color:<?php echo $pct > 75 ? '#d9534f' : ($pct > 50 ? '#f0ad4e' : '#5bc0de'); ?>"><?php echo (int)$item->score; ?> / <?php echo $this->threshold; ?></strong></td>
                    <td style="width: 200px;">
                        <div class="sg-bar-wrap">
                            <div class="sg-bar" style="width:<?php echo $pct; ?>%; background: <?php echo $pct > 75 ? '#d9534f' : ($pct > 50 ? '#f0ad4e' : '#5bc0de'); ?>;"></div>
                            <span class="sg-bar-text"><?php echo $pct; ?>%</span>
                        </div>
                    </td>
                    <td>
                        <?php foreach ($uniqueEvents as $ev => $cnt): ?>
                            <span class="label label-warning"><?php echo htmlspecialchars($ev); ?><?php if ($cnt > 1): ?> ×<?php echo $cnt; endif; ?></span>
                        <?php endforeach; ?>
                    </td>
                    <td><small><?php echo $item->updated_at ? date('Y-m-d H:i:s', (int)$item->updated_at) : '-'; ?></small></td>
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
