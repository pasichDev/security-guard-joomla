<?php
defined('_JEXEC') or die;

$filterAction = $this->state->get('filter.action', '');
$filterSearch = $this->state->get('filter.search', '');

// Count stats by action (for badges)
$db = JFactory::getDbo();
$stats = ['BLOCKED' => 0, 'BLOCKED_RETURN' => 0, 'ALLOWED' => 0, 'total' => 0];
try {
    $q = $db->getQuery(true)
        ->select(['action', 'COUNT(*) AS cnt'])
        ->from($db->quoteName('#__securityguard_log'))
        ->group('action');
    $db->setQuery($q);
    foreach ($db->loadObjectList() as $row) {
        $key = $row->action ?: 'ALLOWED';
        if (isset($stats[$key])) {
            $stats[$key] = (int)$row->cnt;
        }
        $stats['total'] += (int)$row->cnt;
    }
} catch (Exception $e) {}
?>

<form action="<?php echo JRoute::_('index.php?option=com_securityguard&view=logs'); ?>" method="post" name="adminForm" id="adminForm">

<div id="j-sidebar-container" class="span2">
    <?php echo $this->sidebar; ?>
</div>

<div id="j-main-container" class="span10">

    <!-- v1.3.6: Filter bar -->
    <div class="sg-log-filters">
        <div class="sg-log-search">
            <input type="text" name="filter_search" id="filter_search"
                   placeholder="<?php echo JText::_('COM_SECURITYGUARD_FILTER_SEARCH_PH'); ?>"
                   value="<?php echo htmlspecialchars($filterSearch); ?>" />
            <button type="submit" class="btn btn-default">
                <span class="icon-search"></span>
            </button>
        </div>

        <div class="sg-log-action-tabs">
            <a href="<?php echo JRoute::_('index.php?option=com_securityguard&view=logs&filter_action='); ?>"
               class="sg-tab <?php echo $filterAction === '' ? 'active' : ''; ?>">
                <?php echo JText::_('COM_SECURITYGUARD_ALL'); ?>
                <span class="sg-tab-count"><?php echo $stats['total']; ?></span>
            </a>
            <a href="<?php echo JRoute::_('index.php?option=com_securityguard&view=logs&filter_action=blocked_any'); ?>"
               class="sg-tab sg-tab-danger <?php echo $filterAction === 'blocked_any' ? 'active' : ''; ?>">
                <?php echo JText::_('COM_SECURITYGUARD_BLOCKED_ANY'); ?>
                <span class="sg-tab-count"><?php echo $stats['BLOCKED'] + $stats['BLOCKED_RETURN']; ?></span>
            </a>
            <a href="<?php echo JRoute::_('index.php?option=com_securityguard&view=logs&filter_action=BLOCKED'); ?>"
               class="sg-tab sg-tab-danger <?php echo $filterAction === 'BLOCKED' ? 'active' : ''; ?>">
                <?php echo JText::_('COM_SECURITYGUARD_FIRST_BLOCK'); ?>
                <span class="sg-tab-count"><?php echo $stats['BLOCKED']; ?></span>
            </a>
            <a href="<?php echo JRoute::_('index.php?option=com_securityguard&view=logs&filter_action=BLOCKED_RETURN'); ?>"
               class="sg-tab sg-tab-warning <?php echo $filterAction === 'BLOCKED_RETURN' ? 'active' : ''; ?>">
                <?php echo JText::_('COM_SECURITYGUARD_BLOCKED_RETURN'); ?>
                <span class="sg-tab-count"><?php echo $stats['BLOCKED_RETURN']; ?></span>
            </a>
            <a href="<?php echo JRoute::_('index.php?option=com_securityguard&view=logs&filter_action=allowed'); ?>"
               class="sg-tab sg-tab-success <?php echo $filterAction === 'allowed' ? 'active' : ''; ?>">
                <?php echo JText::_('COM_SECURITYGUARD_ALLOWED'); ?>
                <span class="sg-tab-count"><?php echo $stats['ALLOWED']; ?></span>
            </a>
        </div>
    </div>

    <table class="table table-striped table-hover sg-logs">
        <thead>
            <tr>
                <th style="width: 140px;"><?php echo JText::_('COM_SECURITYGUARD_TIMESTAMP'); ?></th>
                <th style="width: 110px;"><?php echo JText::_('COM_SECURITYGUARD_STATUS'); ?></th>
                <th style="width: 130px;"><?php echo JText::_('COM_SECURITYGUARD_IP'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_REASON'); ?></th>
                <th style="width: 70px;"><?php echo JText::_('COM_SECURITYGUARD_METHOD'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_URL'); ?></th>
                <th><?php echo JText::_('COM_SECURITYGUARD_USER_AGENT'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($this->items)): ?>
                <tr><td colspan="7" class="sg-empty-row"><?php echo JText::_('COM_SECURITYGUARD_NO_LOGS'); ?></td></tr>
            <?php else: ?>
                <?php foreach ($this->items as $item):
                    $action = $item->action ?: 'ALLOWED';
                    $cls = '';
                    $icon = '';
                    $label = '';
                    $tooltip = '';
                    if ($action === 'BLOCKED') {
                        $cls = 'sg-status-blocked';
                        $icon = '🛑';
                        $label = 'BLOCKED';
                        $tooltip = JText::_('COM_SECURITYGUARD_TIP_BLOCKED');
                    } elseif ($action === 'BLOCKED_RETURN') {
                        $cls = 'sg-status-return';
                        $icon = '🔁';
                        $label = 'RETURN';
                        $tooltip = JText::_('COM_SECURITYGUARD_TIP_BLOCKED_RETURN');
                    } elseif ($action === 'ALLOWED') {
                        $cls = 'sg-status-allowed';
                        $icon = '✓';
                        $label = 'ALLOWED';
                        $tooltip = JText::_('COM_SECURITYGUARD_TIP_ALLOWED');
                    } else {
                        $cls = 'sg-status-other';
                        $icon = '•';
                        $label = htmlspecialchars($action);
                        $tooltip = '';
                    }
                ?>
                <tr class="<?php echo $cls; ?>">
                    <td><small><?php echo htmlspecialchars($item->created_at); ?></small></td>
                    <td>
                        <span class="sg-status-badge <?php echo $cls; ?>" title="<?php echo htmlspecialchars($tooltip); ?>">
                            <span class="sg-status-icon"><?php echo $icon; ?></span>
                            <span class="sg-status-label"><?php echo $label; ?></span>
                        </span>
                    </td>
                    <td><code><?php echo htmlspecialchars($item->ip); ?></code></td>
                    <td><span class="sg-reason-tag"><?php echo htmlspecialchars($item->reason); ?></span></td>
                    <td><span class="sg-method"><?php echo htmlspecialchars($item->method); ?></span></td>
                    <td><small title="<?php echo htmlspecialchars($item->url); ?>"><?php echo htmlspecialchars(SecurityguardHelper::safeTruncate($item->url, 80)); ?></small></td>
                    <td><small class="sg-ua"><?php echo htmlspecialchars(SecurityguardHelper::safeTruncate($item->user_agent, 60)); ?></small></td>
                </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>

    <?php echo $this->pagination->getListFooter(); ?>

    <input type="hidden" name="task" value="" />
    <input type="hidden" name="boxchecked" value="0" />
    <?php echo JHtml::_('form.token'); ?>
</div>
</form>
