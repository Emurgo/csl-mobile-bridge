// PerformanceTestModule.ts

type PerformanceResult = {
    mean: number;
    median: number;
    stdDev: number;
    marginOfError: number;
};

export const measureSyncFunctionPerformance = (
  func: (...args: any[]) => void,
  runs = 5,
  warmUpRuns = 0,
  ...args: any[]
): PerformanceResult => {
  // Warm-up phase for synchronous functions
  for (let i = 0; i < warmUpRuns; i++) {
    func(...args);
  }

  const times: number[] = [];

  // Actual measurement
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    func(...args);
    const end = performance.now();
    times.push(end - start);
  }

  return calculatePerformanceStats(times, runs);
};

export const measureAsyncFunctionPerformance = async (
  func: (...args: any[]) => Promise<void>,
  runs = 5,
  warmUpRuns = 0,
  ...args: any[]
): Promise<PerformanceResult> => {
  // Warm-up phase for asynchronous functions
  for (let i = 0; i < warmUpRuns; i++) {
    await func(...args);
  }

  const times: number[] = [];

  // Actual measurement
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    await func(...args);
    const end = performance.now();
    times.push(end - start);
  }

  return calculatePerformanceStats(times, runs);
};

const calculatePerformanceStats = (times: number[], runs: number): PerformanceResult => {
  const mean = times.reduce((a, b) => a + b, 0) / runs;
  const sortedTimes = [...times].sort((a, b) => a - b);
  const median = sortedTimes[Math.floor(runs/ 2)] ?? 0;
  const stdDev = Math.sqrt(
    times.map(time => Math.pow(
      time - mean, 2)).reduce((a, b) => a + b) / runs);
  const marginOfError = stdDev / Math.sqrt(runs);

  return { mean, median, stdDev, marginOfError };
};
