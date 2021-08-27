module.exports = {
  transform: {
    '.(ts|tsx)': 'ts-jest',
  },
  testRegex: '(/__tests__/.*|\\.(test|spec|e2e-spec|e2e-test))\\.(ts|tsx|js)$',
  moduleFileExtensions: ['ts', 'tsx', 'js'],
  coveragePathIgnorePatterns: ['/node_modules/', '/test/', '/tools/'],
  // jest-junit is used to generate unit test reports in junit format,
  // which GitLab can store in Pipeline history.
  reporters: ['default', 'jest-junit'],
  coverageThreshold: {
    global: {
      lines: 80,
      statements: 80,
    },
  },
  collectCoverage: true,
  globals: {
    'ts-jest': {
      tsconfig: '<rootDir>/tsconfig.test.json',
      diagnostics: 'pretty',
    },
  },
}
