# Password Strength Report Uses Mature Libraries

Password Strength Reports are generated with mature password-estimation libraries where available, such as zxcvbn-style implementations, but the estimator is not part of the Keyring or Data Envelope format. V1 standardizes the report shape and shared test cases rather than requiring TypeScript, Python, and Kotlin to call the exact same implementation.
