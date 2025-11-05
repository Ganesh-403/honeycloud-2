# Generates sample data
sample_events = [
    {'id':1,'source_ip':'10.0.0.1','service':'ssh','severity':'low'},
    {'id':2,'source_ip':'10.0.0.2','service':'http','severity':'medium'},
]

if __name__=='__main__':
    import json
    print(json.dumps(sample_events, indent=2))
