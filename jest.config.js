module.exports = {
  testEnvironment: "node",           // node environment for backend tests
  testMatch: ["**/test/**/*.test.js"], // match test files in /test
  verbose: true,                     // show detailed test results
  setupFilesAfterEnv: ['<rootDir>/test/setup.js'],
  collectCoverage: true,
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/index.js',        
  ],
  coverageDirectory: 'coverage',
  coverageThreshold: {
    global: { branches: 40, functions: 30, lines: 50, statements: 50 }
  },
  coverageReporters: ['text', 'lcov'],
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: 'test-results',
      outputName: 'junit.xml'
    }]
  ]
};
