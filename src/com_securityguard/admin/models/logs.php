<?php
defined('_JEXEC') or die;

class SecurityguardModelLogs extends JModelList
{
    public function __construct($config = array())
    {
        if (empty($config['filter_fields'])) {
            $config['filter_fields'] = array(
                'id', 'ip', 'reason', 'action', 'created_at'
            );
        }
        parent::__construct($config);
    }

    protected function populateState($ordering = 'created_at', $direction = 'DESC')
    {
        $app = JFactory::getApplication();

        $search = $app->getUserStateFromRequest($this->context . '.filter.search', 'filter_search', '');
        $this->setState('filter.search', $search);

        // v1.3.6: action filter
        $filterAction = $app->getUserStateFromRequest($this->context . '.filter.action', 'filter_action', '');
        $this->setState('filter.action', $filterAction);

        parent::populateState($ordering, $direction);
    }

    protected function getListQuery()
    {
        $db = $this->getDbo();
        $query = $db->getQuery(true);

        $query->select('*')
              ->from($db->quoteName('#__securityguard_log'));

        $search = $this->getState('filter.search');
        if (!empty($search)) {
            $search = $db->quote('%' . $db->escape($search, true) . '%');
            $query->where('(' . $db->quoteName('ip') . ' LIKE ' . $search
                . ' OR ' . $db->quoteName('reason') . ' LIKE ' . $search
                . ' OR ' . $db->quoteName('url') . ' LIKE ' . $search . ')');
        }

        // v1.3.6: action filter
        $filterAction = $this->getState('filter.action');
        if (!empty($filterAction)) {
            if ($filterAction === 'blocked_any') {
                // any block (BLOCKED or BLOCKED_RETURN)
                $query->where($db->quoteName('action') . ' IN (' . $db->quote('BLOCKED') . ', ' . $db->quote('BLOCKED_RETURN') . ')');
            } elseif ($filterAction === 'allowed') {
                // explicit ALLOWED, or empty (legacy entries)
                $query->where('(' . $db->quoteName('action') . ' = ' . $db->quote('ALLOWED')
                    . ' OR ' . $db->quoteName('action') . ' IS NULL'
                    . ' OR ' . $db->quoteName('action') . ' = ' . $db->quote('') . ')');
            } else {
                $query->where($db->quoteName('action') . ' = ' . $db->quote($filterAction));
            }
        }

        $orderCol = $this->state->get('list.ordering', 'created_at');
        $orderDir = $this->state->get('list.direction', 'DESC');
        $query->order($db->escape($orderCol) . ' ' . $db->escape($orderDir));

        return $query;
    }
}
