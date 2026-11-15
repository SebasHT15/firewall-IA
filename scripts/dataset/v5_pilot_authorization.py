"""D73-ratified calibration contract: exact parameters, 10% quotas, no training.

D73 activates the schema definition. Individual permissions remain mandatory.
"""
SCHEMA = 'v5-pilot-build-authorization/v1-PROPOSED'
ACTIVE_SCHEMA = SCHEMA  # D73


def check(auth, *, generator_sha, split_sha, preregistration_sha, generator_config):
    errors=[]
    def error(detail):errors.append({'code':'PILOT_AUTHORIZATION','detail':detail})
    if ACTIVE_SCHEMA is None:error('pilot calibration schema has not been ratified')
    if not isinstance(auth,dict):
        error('pilot authorization record missing');return errors
    if auth.get('schema') != ACTIVE_SCHEMA:error('pilot authorization schema mismatch')
    for field,want in {'scope':'PILOT_BUILD','purpose':'CALIBRATION_ONLY',
                       'generator_config_sha256':generator_sha,'split_config_sha256':split_sha,
                       'preregistration_sha256':preregistration_sha}.items():
        if not want or auth.get(field)!=want:error(f'{field} does not match effective pilot inputs')
    if auth.get('allows_training') is not False or auth.get('final_dataset') is not False:
        error('calibration must explicitly prohibit training and final-dataset status')
    for field in ('authorized_by','date','owner_decision'):
        if not isinstance(auth.get(field),str) or not auth[field].strip():error(f'{field} missing')
    if auth.get('pilot_fraction') != {'numerator':1,'denominator':10}:
        error('pilot_fraction must explicitly fix the proposed 10% quota fraction')
    full=auth.get('full_pairs_per_cluster_category')
    if type(full) is not int or full<1:
        error('positive integer full quota is required to define the 10% pilot')
    else:
        expected=(full+9)//10
        if generator_config.get('quota',{}).get('pairs_per_cluster_category') != expected:
            error('pilot quota must equal ceil(full quota / 10)')
    return errors
