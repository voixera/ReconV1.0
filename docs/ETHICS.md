# Ethics & Legal Use

VXRecon is a passive reconnaissance and defensive research framework. It exists
to help defenders, researchers and investigators understand their own or
authorised digital footprints.

## Permitted use

- Assessing infrastructure you own or operate.
- Authorised security assessments where you have written permission.
- Academic research using public data on targets you are allowed to study.
- Personal digital-footprint audits.

## Prohibited use

VXRecon must not be used to:

- gain or attempt unauthorised access to any system,
- attack, disrupt or degrade any service,
- harass, stalk or profile individuals without consent,
- circumvent authentication, CAPTCHA or access controls,
- gather data in violation of applicable law or terms of service.

## Design constraints that enforce ethics

- Passive only: VXRecon reads public data; it does not modify targets.
- No brute-forcing, exploitation, or evasion capabilities exist.
- All requests are read-only, rate-limited and time-bounded.
- The User-Agent identifies the tool honestly.
- No telemetry: your investigations never leave your machine.

## Responsibility

You are solely responsible for how you use this tool and for complying with all
applicable laws, regulations and third-party terms of service. The maintainers
accept no liability for misuse.

If a capability you want would require unauthorised access, reframe it as a
passive alternative or leave it out.
