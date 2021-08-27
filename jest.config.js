module.exports = {
  transform: {
    '.(ts|tsx)': 'ts-jest',
  },
  testRegex: '(/__tests__/.*|\\.(test|spec|e2e-spec|e2e-test))\\.(ts|tsx|js)$',
  moduleFileExtensions: ['ts', 'tsx', 'js'],
  coveragePathIgnorePatterns: ['/node_modules/', '/test/', '/tools/'],
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
