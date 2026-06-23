module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'perf', 'refactor', 'chore', 'ci', 'docs', 'test', 'style', 'build', 'revert'],
    ],
    // Scope is required for this repository.
    'scope-empty': [2, 'never'],
    'scope-enum': [
      2,
      'always',
      [
        'component', // com_securityguard (admin UI, controller, models, views)
        'plugin',    // plg_system_securityguard
        'waf',       // request filtering / blocking rules
        'honeypot',
        'scoring',   // behavior scoring
        'dashboard',
        'traffic',   // traffic monitor
        'ddos',
        'geo',       // geo-tracking
        'sql',       // install/update schema
        'i18n',      // language files
        'build',     // build script / packaging
        'ci',        // workflows
        'deps',      // dependency updates
        'release',   // automated commits made by semantic-release
        'repo',      // repository meta: README, funding, license, contributing
      ],
    ],
    'subject-min-length': [2, 'always', 10],
    'subject-full-stop': [2, 'never', '.'],
    'header-max-length': [2, 'always', 100],
  },
};
