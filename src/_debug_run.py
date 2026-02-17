import PAM, test, json
results = []
try:
    test.run_basic_calls(results)
except Exception as e:
    # record exception info
    results.append(('EXC', repr(e)))
with open('test_results_debug.json', 'w') as fh:
    json.dump(results, fh, indent=2)
print('Wrote test_results_debug.json')
