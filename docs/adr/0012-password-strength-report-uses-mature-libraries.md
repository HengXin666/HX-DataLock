# Password Strength Report Uses Mature Libraries

Password Strength Reports are generated with mature password-estimation libraries where available, such as zxcvbn-style implementations, but the estimator is not part of the Keyring or Data Envelope format. V1 standardizes the report shape and shared test cases rather than requiring TypeScript, Python, and Kotlin to call the exact same implementation.

Where no mature library is bundled, the estimator must still consult dictionary membership rather than only counting length and alphabet size. The reason is on record: the length-and-alphabet estimator reported 27-42 bits for passwords that the crack audit recovered from dictionary ranks 0-2006, meaning it overestimated resistance by about 2^28 for the worst offenders while the entire security budget of a leaked Keyring rests on that password. Dictionary membership caps the estimate before any length term is credited.
