

import argparse 
import hashlib 
import time 
import ssl 
import socket 
from typing import List ,Tuple ,Optional ,Dict ,Any 

REDIS_HOST ="<HOST_IP>"
REDIS_PORT =6379 
REDIS_CA_CERT ="<REDIS_TLS_DIR>/ca.crt"
REDIS_CERT ="<REDIS_TLS_DIR>/server.crt"
REDIS_KEY ="<REDIS_TLS_DIR>/server.key"

class RedisClient :
    """Simple Redis client with TLS support"""

    def __init__ (self ,host :str ,port :int ,ca_cert :str ,cert :str ,key :str ):
        self .host =host 
        self .port =port 

        context =ssl .create_default_context (ssl .Purpose .SERVER_AUTH )
        context .load_verify_locations (ca_cert )
        context .load_cert_chain (certfile =cert ,keyfile =key )
        context .check_hostname =False 
        context .verify_mode =ssl .CERT_OPTIONAL 

        sock =socket .create_connection ((host ,port ))
        self .sock =context .wrap_socket (sock ,server_hostname =host )

    def command (self ,*args )->Any :
        """Send RESP command and get response"""

        cmd =f"*{len(args)}\r\n"
        for arg in args :
            arg_str =str (arg )
            cmd +=f"${len(arg_str)}\r\n{arg_str}\r\n"

        self .sock .sendall (cmd .encode ())
        return self ._read_response ()

    def _read_response (self )->Any :
        """Read RESP response"""
        line =self ._read_line ()
        resp_type =line [0 ]
        data =line [1 :]

        if resp_type =='+':
            return data 
        elif resp_type =='-':
            raise Exception (f"Redis error: {data}")
        elif resp_type ==':':
            return int (data )
        elif resp_type =='$':
            length =int (data )
            if length ==-1 :
                return None 
            result =self ._read_bytes (length )
            self ._read_bytes (2 )
            return result .decode ()
        elif resp_type =='*':
            count =int (data )
            if count ==-1 :
                return None 
            return [self ._read_response ()for _ in range (count )]
        else :
            raise Exception (f"Unknown response type: {resp_type}")

    def _read_line (self )->str :
        """Read until CRLF"""
        buf =b""
        while not buf .endswith (b"\r\n"):
            buf +=self .sock .recv (1 )
        return buf [:-2 ].decode ()

    def _read_bytes (self ,n :int )->bytes :
        """Read exactly n bytes"""
        buf =b""
        while len (buf )<n :
            buf +=self .sock .recv (n -len (buf ))
        return buf 

    def keys (self ,pattern :str )->List [str ]:
        return self .command ("KEYS",pattern )or []

    def hgetall (self ,key :str )->Dict [str ,str ]:
        result =self .command ("HGETALL",key )
        if not result :
            return {}
        return dict (zip (result [::2 ],result [1 ::2 ]))

    def lrange (self ,key :str ,start :int ,end :int )->List [str ]:
        return self .command ("LRANGE",key ,start ,end )or []

    def llen (self ,key :str )->int :
        return self .command ("LLEN",key )

    def lindex (self ,key :str ,index :int )->str :
        return self .command ("LINDEX",key ,index )

    def hmget (self ,key :str ,*fields )->List [str ]:
        """Get specific fields from hash - O(n) where n is number of fields"""
        result =self .command ("HMGET",key ,*fields )
        return result if result else []

    def close (self ):
        self .sock .close ()

def sha256 (data :bytes )->bytes :
    """Compute SHA256 hash"""
    return hashlib .sha256 (data ).digest ()

def hash_pair (left :bytes ,right :bytes )->bytes :
    """Hash two nodes together for Merkle tree"""
    return sha256 (left +right )

def build_merkle_tree (leaf_hashes :List [bytes ])->Tuple [bytes ,List [List [bytes ]]]:
    """
    Build Merkle tree from leaf hashes (matches Rust implementation exactly)
    Returns (root_hash, all_levels)
    """
    if not leaf_hashes :
        return bytes (32 ),[]

    current_level =leaf_hashes [:]
    levels =[current_level [:]]

    if len (current_level )%2 ==1 :
        current_level .append (current_level [-1 ])

    while len (current_level )>1 :
        next_level =[]
        for i in range (0 ,len (current_level ),2 ):
            left =current_level [i ]
            right =current_level [i +1 ]if i +1 <len (current_level )else left 
            next_level .append (hash_pair (left ,right ))

        levels .append (next_level )
        current_level =next_level 

        if len (current_level )>1 and len (current_level )%2 ==1 :
            current_level .append (current_level [-1 ])

    return current_level [0 ],levels 

def compute_leaf_hash (record :Dict [str ,str ])->bytes :
    """Compute leaf hash from record data - MUST match Rust's {:.6} format"""

    pid =record ['pid']
    cpu_time =float (record ['cpu_time'])
    energy =float (record ['energy'])
    power =float (record ['power'])
    vm_name =record ['vm_name']
    timestamp =record ['timestamp']

    data =f"{pid}|{cpu_time:.6f}|{energy:.6f}|{power:.6f}|{vm_name}|{timestamp}"
    return sha256 (data .encode ())

def parse_record (record_str :str )->Dict [str ,str ]:
    """Parse record string: leaf_hash|pid|cpu_time|energy|power|vm_name|timestamp"""
    parts =record_str .split ('|')
    return {
    'leaf_hash':parts [0 ],
    'pid':parts [1 ],
    'cpu_time':parts [2 ],
    'energy':parts [3 ],
    'power':parts [4 ],
    'vm_name':parts [5 ],
    'timestamp':parts [6 ]if len (parts )>6 else ''
    }

def verify_block (redis :RedisClient ,block_id :int )->Tuple [bool ,Dict [str ,Any ]]:
    """
    Verify a block's Merkle tree integrity
    Returns (is_valid, details)
    """
    start_time =time .time ()

    block_key =f"block:{block_id}"
    block_data =redis .hgetall (block_key )

    if not block_data :
        return False ,{"error":f"Block {block_id} not found"}

    stored_merkle_root =block_data .get ('merkle_root','')
    stored_record_count =int (block_data .get ('record_count',0 ))
    block_number =block_data .get ('block_number','unknown')
    vm_name =block_data .get ('vm_name','unknown')

    records_key =f"records:{block_id}"
    record_count =redis .llen (records_key )

    if record_count !=stored_record_count :
        return False ,{
        "error":f"Record count mismatch: stored={stored_record_count}, actual={record_count}"
        }

    fetch_start =time .time ()
    raw_records =redis .lrange (records_key ,0 ,-1 )
    fetch_time =time .time ()-fetch_start 

    parse_start =time .time ()
    records =[parse_record (r )for r in raw_records ]
    stored_leaf_hashes =[bytes .fromhex (r ['leaf_hash'])for r in records ]
    parse_time =time .time ()-parse_start 

    tree_start =time .time ()
    computed_root ,levels =build_merkle_tree (stored_leaf_hashes )
    computed_root_hex =computed_root .hex ()
    tree_time =time .time ()-tree_start 

    total_time =time .time ()-start_time 

    is_valid =computed_root_hex ==stored_merkle_root 

    return is_valid ,{
    "block_id":block_id ,
    "block_number":block_number ,
    "vm_name":vm_name ,
    "record_count":record_count ,
    "tree_height":len (levels ),
    "stored_root":stored_merkle_root [:32 ]+"...",
    "computed_root":computed_root_hex [:32 ]+"...",
    "is_valid":is_valid ,
    "timing":{
    "fetch_ms":fetch_time *1000 ,
    "parse_ms":parse_time *1000 ,
    "tree_build_ms":tree_time *1000 ,
    "total_ms":total_time *1000 
    }
    }

def verify_chain (redis :RedisClient )->Tuple [bool ,List [Dict [str ,Any ]]]:
    """Verify the chain of blocks (chained roots)"""
    results =[]

    block_keys =sorted ([k for k in redis .keys ("block:*")],
    key =lambda k :int (k .split (':')[1 ]))

    prev_chained_root ="0"*64 

    for block_key in block_keys :
        block_id =int (block_key .split (':')[1 ])
        block_data =redis .hgetall (block_key )

        stored_prev =block_data .get ('prev_chained_root','')
        stored_merkle =block_data .get ('merkle_root','')
        stored_chained =block_data .get ('chained_root','')

        if stored_prev !=prev_chained_root :
            results .append ({
            "block_id":block_id ,
            "chain_valid":False ,
            "error":f"Chain broken: expected prev={prev_chained_root[:16]}..., got={stored_prev[:16]}..."
            })
            return False ,results 

        computed_chained =sha256 (
        bytes .fromhex (stored_prev )+bytes .fromhex (stored_merkle )
        ).hex ()

        chain_valid =computed_chained ==stored_chained 

        results .append ({
        "block_id":block_id ,
        "merkle_root":stored_merkle [:16 ]+"...",
        "chained_root":stored_chained [:16 ]+"...",
        "chain_valid":chain_valid 
        })

        if not chain_valid :
            return False ,results 

        prev_chained_root =stored_chained 

    return True ,results 

def calculate_proof_path_keys (record_idx :int ,tree_height :int )->List [Tuple [str ,str ]]:
    """
    Calculate the keys needed for merkle proof path.
    Returns list of (sibling_key, self_key) tuples for HMGET.
    """
    keys =[]
    position =record_idx 

    for level in range (tree_height -1 ):
        if position %2 ==0 :
            sibling_pos =position +1 
        else :
            sibling_pos =position -1 

        sibling_key =f"{level}:{sibling_pos}"
        self_key =f"{level}:{position}"
        keys .append ((sibling_key ,self_key ))
        position =position //2 

    return keys 

def fetch_proof_nodes (redis :RedisClient ,block_id :int ,record_idx :int ,tree_height :int )->Dict [str ,str ]:
    """
    Fetch ONLY the O(log n) nodes needed for merkle proof using HMGET.
    This is the key optimization - avoids fetching all nodes with HGETALL.
    """
    path_keys =calculate_proof_path_keys (record_idx ,tree_height )

    all_keys =[]
    for sibling_key ,self_key in path_keys :
        all_keys .append (sibling_key )
        all_keys .append (self_key )

    merkle_key =f"merkle:{block_id}"
    values =redis .hmget (merkle_key ,*all_keys )

    result ={}
    for i ,key in enumerate (all_keys ):
        if values [i ]:
            result [key ]=values [i ]

    return result 

def verify_record_logn_cached (redis :RedisClient ,block_id :int ,record_idx :int ,
block_data :Dict [str ,str ]=None ,
merkle_nodes :Dict [str ,str ]=None )->Tuple [bool ,Dict [str ,Any ]]:
    """
    Verify a single record using O(log n) Merkle proof with optional caching.
    
    Instead of rebuilding the entire tree, we only fetch:
    - The single record (1 item)
    - log(n) sibling hashes from the merkle tree (using HMGET, not HGETALL)
    
    If block_data and merkle_nodes are provided, they are reused (for batch verification).
    This avoids redundant Redis calls when verifying multiple records from the same block.
    """
    start_time =time .time ()
    timing ={}

    meta_start =time .time ()
    if block_data is None :
        block_key =f"block:{block_id}"
        block_data =redis .hgetall (block_key )
    timing ['meta_fetch_ms']=(time .time ()-meta_start )*1000 

    if not block_data :
        return False ,{"error":f"Block {block_id} not found"}

    stored_merkle_root =block_data .get ('merkle_root','')
    record_count =int (block_data .get ('record_count',0 ))
    tree_height =int (block_data .get ('tree_height',0 ))

    if record_idx <0 or record_idx >=record_count :
        return False ,{"error":f"Record index {record_idx} out of range (0-{record_count-1})"}

    fetch_start =time .time ()
    records_key =f"records:{block_id}"
    single_record =redis .lindex (records_key ,record_idx )
    timing ['record_fetch_ms']=(time .time ()-fetch_start )*1000 

    if not single_record :
        return False ,{"error":f"Record {record_idx} not found"}

    record =parse_record (single_record )
    stored_leaf_hash =bytes .fromhex (record ['leaf_hash'])

    hash_start =time .time ()
    computed_leaf_hash =compute_leaf_hash (record )
    timing ['hash_compute_ms']=(time .time ()-hash_start )*1000 

    leaf_hash_valid =(computed_leaf_hash ==stored_leaf_hash )

    nodes_start =time .time ()
    if merkle_nodes is None :
        merkle_nodes =fetch_proof_nodes (redis ,block_id ,record_idx ,tree_height )
    timing ['nodes_fetch_ms']=(time .time ()-nodes_start )*1000 

    proof_start =time .time ()

    padded_count =record_count 
    if padded_count %2 ==1 :
        padded_count +=1 

    position =record_idx 
    current_hash =computed_leaf_hash 
    proof_path =[]
    hashes_computed =0 

    for level in range (tree_height -1 ):

        if position %2 ==0 :
            sibling_pos =position +1 
            is_left =True 
        else :
            sibling_pos =position -1 
            is_left =False 

        sibling_key =f"{level}:{sibling_pos}"
        sibling_data =merkle_nodes .get (sibling_key ,'')

        if sibling_data :
            sibling_hash =bytes .fromhex (sibling_data .split ('|')[0 ])
        else :

            node_key =f"{level}:{position}"
            node_data =merkle_nodes .get (node_key ,'')
            if node_data :
                sibling_hash =bytes .fromhex (node_data .split ('|')[0 ])
            else :

                sibling_hash =current_hash 

        proof_path .append ({
        "level":level ,
        "position":position ,
        "sibling_pos":sibling_pos ,
        "is_left":is_left ,
        "sibling_hash":sibling_hash .hex ()[:16 ]+"..."
        })

        if is_left :
            current_hash =hash_pair (current_hash ,sibling_hash )
        else :
            current_hash =hash_pair (sibling_hash ,current_hash )

        hashes_computed +=1 

        position =position //2 

    timing ['proof_verify_ms']=(time .time ()-proof_start )*1000 
    timing ['total_ms']=(time .time ()-start_time )*1000 

    computed_root_hex =current_hash .hex ()
    merkle_proof_valid =(computed_root_hex ==stored_merkle_root )

    is_valid =leaf_hash_valid and merkle_proof_valid 

    return is_valid ,{
    "block_id":block_id ,
    "record_idx":record_idx ,
    "record_count":record_count ,
    "tree_height":tree_height ,
    "proof_length":len (proof_path ),
    "hashes_computed":hashes_computed ,
    "nodes_fetched":len (merkle_nodes ),
    "complexity":f"O(log n) = O(log {record_count}) = {hashes_computed} hashes",
    "leaf_hash_valid":leaf_hash_valid ,
    "merkle_proof_valid":merkle_proof_valid ,
    "stored_leaf":stored_leaf_hash .hex ()[:32 ]+"...",
    "computed_leaf":computed_leaf_hash .hex ()[:32 ]+"...",
    "stored_root":stored_merkle_root [:32 ]+"...",
    "computed_root":computed_root_hex [:32 ]+"...",
    "is_valid":is_valid ,
    "record_data":{
    "pid":record ['pid'],
    "energy":record ['energy'],
    "vm_name":record ['vm_name'],
    "timestamp":record ['timestamp']
    },
    "proof_path":proof_path ,
    "timing":timing 
    }

def verify_record_logn (redis :RedisClient ,block_id :int ,record_idx :int )->Tuple [bool ,Dict [str ,Any ]]:
    """Wrapper for backward compatibility - calls cached version without cache."""
    return verify_record_logn_cached (redis ,block_id ,record_idx ,None ,None )

def verify_block_records_collective (redis :RedisClient ,block_id :int ,
target_indices :List [int ]=None )->Tuple [bool ,Dict [str ,Any ]]:
    """
    Verify records COLLECTIVELY by rebuilding the full Merkle tree ONCE.
    
    This is O(n) for the block but more efficient than doing m x O(log n) 
    individual proofs when verifying many records in the same block.
    
    Args:
        redis: Redis client
        block_id: Block ID to verify
        target_indices: Optional list of specific record indices to verify.
                       If None, verifies all records.
    
    Returns: (all_valid, details)
    """
    start_time =time .time ()
    timing ={}

    meta_start =time .time ()
    block_key =f"block:{block_id}"
    block_data =redis .hgetall (block_key )
    timing ['meta_fetch_ms']=(time .time ()-meta_start )*1000 

    if not block_data :
        return False ,{"error":f"Block {block_id} not found"}

    stored_merkle_root =block_data .get ('merkle_root','')
    stored_record_count =int (block_data .get ('record_count',0 ))

    fetch_start =time .time ()
    records_key =f"records:{block_id}"
    raw_records =redis .lrange (records_key ,0 ,-1 )
    timing ['records_fetch_ms']=(time .time ()-fetch_start )*1000 

    if len (raw_records )!=stored_record_count :
        return False ,{"error":f"Record count mismatch: stored={stored_record_count}, actual={len(raw_records)}"}

    parse_start =time .time ()
    records =[parse_record (r )for r in raw_records ]

    computed_leaves =[]
    leaf_mismatches =[]

    for idx ,rec in enumerate (records ):
        stored_leaf =bytes .fromhex (rec ['leaf_hash'])
        computed_leaf =compute_leaf_hash (rec )
        computed_leaves .append (computed_leaf )

        if target_indices is None or idx in target_indices :
            if computed_leaf !=stored_leaf :
                leaf_mismatches .append ({
                'index':idx ,
                'stored':stored_leaf .hex ()[:16 ],
                'computed':computed_leaf .hex ()[:16 ]
                })

    timing ['parse_compute_ms']=(time .time ()-parse_start )*1000 

    tree_start =time .time ()
    computed_root ,levels =build_merkle_tree (computed_leaves )
    computed_root_hex =computed_root .hex ()
    timing ['tree_build_ms']=(time .time ()-tree_start )*1000 

    merkle_valid =(computed_root_hex ==stored_merkle_root )

    all_valid =merkle_valid and len (leaf_mismatches )==0 

    timing ['total_ms']=(time .time ()-start_time )*1000 

    verified_indices =target_indices if target_indices else list (range (len (records )))

    return all_valid ,{
    "block_id":block_id ,
    "total_records":len (records ),
    "verified_count":len (verified_indices ),
    "tree_height":len (levels ),
    "merkle_valid":merkle_valid ,
    "leaf_mismatches":len (leaf_mismatches ),
    "stored_root":stored_merkle_root [:32 ]+"...",
    "computed_root":computed_root_hex [:32 ]+"...",
    "complexity":f"O(n) = O({len(records)}) - single tree rebuild",
    "timing":timing 
    }

def verify_records_batch (redis :RedisClient ,records :list ,use_collective :bool =True )->Tuple [int ,int ,list ,float ]:
    """
    Verify multiple records efficiently.
    
    If use_collective=True (default), uses collective verification:
    - Rebuilds Merkle tree ONCE per block (O(n) per block)
    - More efficient when verifying many records from same block
    
    If use_collective=False, uses individual O(log n) proofs with caching.
    
    Returns: (verified_count, failed_count, failed_records, total_time_ms)
    """
    start_time =time .time ()

    records_by_block ={}
    for rec in records :
        block_id =rec ['block_id']
        if block_id not in records_by_block :
            records_by_block [block_id ]=[]
        records_by_block [block_id ].append (rec )

    verified_count =0 
    failed_records =[]

    if use_collective :

        for block_id ,block_records in records_by_block .items ():
            target_indices =[rec ['record_index']for rec in block_records ]

            is_valid ,details =verify_block_records_collective (redis ,block_id ,target_indices )

            if is_valid :
                verified_count +=len (block_records )
            else :

                for rec in block_records :
                    failed_records .append ((block_id ,rec ['record_index'],
                    f"Block verification failed: {details.get('error', 'merkle mismatch')}"))
    else :

        for block_id ,block_records in records_by_block .items ():

            block_key =f"block:{block_id}"
            block_data =redis .hgetall (block_key )

            merkle_key =f"merkle:{block_id}"
            merkle_nodes =redis .hgetall (merkle_key )

            for rec in block_records :
                is_valid ,details =verify_record_logn_cached (
                redis ,block_id ,rec ['record_index'],
                block_data ,merkle_nodes 
                )
                if is_valid :
                    verified_count +=1 
                else :
                    failed_records .append ((block_id ,rec ['record_index'],details .get ('error','Unknown')))

    total_time =(time .time ()-start_time )*1000 
    failed_count =len (failed_records )

    return verified_count ,failed_count ,failed_records ,total_time 

def verify_chain_to_block (redis :RedisClient ,target_block :int )->Tuple [bool ,Dict [str ,Any ]]:
    """
    Verify the hash chain from genesis up to and including target_block.
    Returns (is_valid, {blocks_verified, chain_details}).
    """
    start_time =time .time ()
    chain_details =[]

    block_keys =sorted ([k for k in redis .keys ("block:*")],
    key =lambda k :int (k .split (':')[1 ]))

    prev_chained_root ="0"*64 

    for block_key in block_keys :
        block_id =int (block_key .split (':')[1 ])
        if block_id >target_block :
            break 

        block_data =redis .hgetall (block_key )

        stored_prev =block_data .get ('prev_chained_root','')
        stored_merkle =block_data .get ('merkle_root','')
        stored_chained =block_data .get ('chained_root','')

        if stored_prev !=prev_chained_root :
            return False ,{
            "blocks_verified":len (chain_details ),
            "error":f"Chain broken at block {block_id}: expected prev={prev_chained_root[:16]}..., got={stored_prev[:16]}...",
            "chain_details":chain_details ,
            "timing_ms":(time .time ()-start_time )*1000 
            }

        computed_chained =sha256 (
        bytes .fromhex (stored_prev )+bytes .fromhex (stored_merkle )
        ).hex ()

        chain_valid =computed_chained ==stored_chained 

        chain_details .append ({
        "block_id":block_id ,
        "merkle_root":stored_merkle [:16 ]+"...",
        "chained_root":stored_chained [:16 ]+"...",
        "valid":chain_valid 
        })

        if not chain_valid :
            return False ,{
            "blocks_verified":len (chain_details ),
            "error":f"Chained root mismatch at block {block_id}",
            "chain_details":chain_details ,
            "timing_ms":(time .time ()-start_time )*1000 
            }

        prev_chained_root =stored_chained 

    return True ,{
    "blocks_verified":len (chain_details ),
    "target_block":target_block ,
    "chain_details":chain_details ,
    "timing_ms":(time .time ()-start_time )*1000 
    }

def verify_record_full (redis :RedisClient ,block_id :int ,record_idx :int )->Tuple [bool ,Dict [str ,Any ]]:
    """
    Full verification of a record:
    1. Verify hash chain from genesis to the block (proves block root authenticity)
    2. Verify Merkle proof (proves record is in the block)
    
    This is the complete verification that guarantees data integrity.
    """
    start_time =time .time ()

    chain_valid ,chain_result =verify_chain_to_block (redis ,block_id )

    if not chain_valid :
        return False ,{
        "error":f"Chain verification failed: {chain_result.get('error', 'Unknown')}",
        "chain_verification":chain_result ,
        "merkle_verification":None 
        }

    merkle_valid ,merkle_result =verify_record_logn (redis ,block_id ,record_idx )

    total_time =time .time ()-start_time 

    is_valid =chain_valid and merkle_valid 

    return is_valid ,{
    "is_valid":is_valid ,
    "chain_verification":{
    "valid":chain_valid ,
    "blocks_verified":chain_result .get ('blocks_verified',0 ),
    "timing_ms":chain_result .get ('timing_ms',0 )
    },
    "merkle_verification":merkle_result ,
    "timing":{
    "chain_ms":chain_result .get ('timing_ms',0 ),
    "merkle_ms":merkle_result .get ('timing',{}).get ('total_ms',0 ),
    "total_ms":total_time *1000 
    }
    }

def find_blocks_by_date (redis :RedisClient ,date_str :str )->List [int ]:
    """Find blocks containing records from a specific date"""
    matching_blocks =[]

    block_keys =redis .keys ("block:*")
    for block_key in block_keys :
        block_id =int (block_key .split (':')[1 ])
        records_key =f"records:{block_id}"

        first_record =redis .lrange (records_key ,0 ,0 )
        if first_record :
            record =parse_record (first_record [0 ])
            if date_str in record .get ('timestamp',''):
                matching_blocks .append (block_id )

    return sorted (matching_blocks )

def find_records_by_date (redis :RedisClient ,date_str :str )->List [Dict [str ,Any ]]:
    """
    Find all records matching a date string.
    Returns list of dicts: {block_id, record_index, record_data}
    """
    matching_records =[]

    block_keys =redis .keys ("block:*")
    for block_key in sorted (block_keys ,key =lambda k :int (k .split (':')[1 ])):
        block_id =int (block_key .split (':')[1 ])
        records_key =f"records:{block_id}"

        all_records =redis .lrange (records_key ,0 ,-1 )

        for idx ,record_str in enumerate (all_records ):
            record =parse_record (record_str )

            if date_str in record .get ('timestamp',''):
                matching_records .append ({
                'block_id':block_id ,
                'record_index':idx ,
                'record':record 
                })

    return matching_records 

def parse_timestamp (ts_str :str )->Optional [float ]:
    """Parse timestamp string to Unix timestamp. Returns None if invalid."""
    from datetime import datetime 
    formats =[
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d",
    ]
    for fmt in formats :
        try :
            return datetime .strptime (ts_str ,fmt ).timestamp ()
        except ValueError :
            continue 
    return None 

def find_records_by_date_range (redis :RedisClient ,start_time :str ,end_time :str )->List [Dict [str ,Any ]]:
    """
    Find all records within a date/time range.
    Args:
        start_time: Start datetime (e.g., "2026-02-14 00:00:00")
        end_time: End datetime (e.g., "2026-02-14 23:59:59")
    Returns list of dicts: {block_id, record_index, record_data}
    """
    matching_records =[]

    start_ts =parse_timestamp (start_time )
    end_ts =parse_timestamp (end_time )

    if start_ts is None or end_ts is None :
        print (f"[!] Invalid date format. Use: YYYY-MM-DD HH:MM:SS")
        return []

    block_keys =redis .keys ("block:*")
    for block_key in sorted (block_keys ,key =lambda k :int (k .split (':')[1 ])):
        block_id =int (block_key .split (':')[1 ])
        records_key =f"records:{block_id}"

        all_records =redis .lrange (records_key ,0 ,-1 )

        for idx ,record_str in enumerate (all_records ):
            record =parse_record (record_str )
            record_ts =parse_timestamp (record .get ('timestamp',''))

            if record_ts is not None and start_ts <=record_ts <=end_ts :
                matching_records .append ({
                'block_id':block_id ,
                'record_index':idx ,
                'record':record 
                })

    return matching_records 

def find_block_for_index (redis :RedisClient ,global_index :int )->Tuple [int ,int ,int ]:
    """
    Find which block contains a global record index.
    Returns: (block_id, record_index_within_block, total_records)
    """
    block_keys =sorted (redis .keys ("block:*"),key =lambda k :int (k .split (':')[1 ]))

    cumulative =0 
    for block_key in block_keys :
        block_id =int (block_key .split (':')[1 ])
        block_data =redis .hgetall (block_key )
        record_count =int (block_data .get ('record_count',0 ))

        if cumulative +record_count >global_index :

            record_idx =global_index -cumulative 
            total =cumulative +record_count 

            for remaining_key in block_keys [block_keys .index (block_key )+1 :]:
                rem_data =redis .hgetall (remaining_key )
                total +=int (rem_data .get ('record_count',0 ))
            return block_id ,record_idx ,total 

        cumulative +=record_count 

    return -1 ,-1 ,cumulative 

def main ():
    parser =argparse .ArgumentParser (description ="Verify Redis energy data cryptographically")
    parser .add_argument ("--block",type =int ,help ="Verify specific block ID (O(n) full tree)")
    parser .add_argument ("--record",type =str ,help ="Verify single record O(log n): BLOCK_ID:RECORD_INDEX")
    parser .add_argument ("--index",type =int ,help ="Verify record by global index (auto-finds block)")
    parser .add_argument ("--from-index",type =int ,help ="Start index for range verification")
    parser .add_argument ("--to-index",type =int ,help ="End index for range verification")
    parser .add_argument ("--date",type =str ,help ="Find and verify blocks by date (YYYY-MM-DD)")
    parser .add_argument ("--from",dest ="from_time",type =str ,help ="Start datetime (YYYY-MM-DD HH:MM:SS)")
    parser .add_argument ("--to",dest ="to_time",type =str ,help ="End datetime (YYYY-MM-DD HH:MM:SS)")
    parser .add_argument ("--all",action ="store_true",help ="Verify all blocks")
    parser .add_argument ("--chain",action ="store_true",help ="Verify block chain integrity")
    parser .add_argument ("--individual",action ="store_true",
    help ="Use individual O(log n) proofs instead of collective tree rebuild (slower for batch)")
    args =parser .parse_args ()

    print ("="*70 )
    print ("Redis Data Cryptographic Verification")
    print ("="*70 )

    connect_start =time .time ()
    print (f"\n[*] Connecting to Redis at {REDIS_HOST}:{REDIS_PORT} (TLS)...")
    redis =RedisClient (REDIS_HOST ,REDIS_PORT ,REDIS_CA_CERT ,REDIS_CERT ,REDIS_KEY )
    connect_time =(time .time ()-connect_start )*1000 
    print (f"[OK] Connected in {connect_time:.2f}ms")

    try :
        if args .chain :
            print ("\n[*] Verifying block chain integrity...")
            chain_start =time .time ()
            is_valid ,results =verify_chain (redis )
            chain_time =(time .time ()-chain_start )*1000 

            for r in results :
                status ="OK"if r .get ('chain_valid')else "FAIL"
                print (f"    Block {r['block_id']}: [{status}] "
                f"merkle={r.get('merkle_root', 'N/A')} "
                f"chained={r.get('chained_root', 'N/A')}")

            print (f"\n[{'OK' if is_valid else 'FAIL'}] Chain verification: {'VALID' if is_valid else 'INVALID'}")
            print (f"    Time: {chain_time:.2f}ms")

        elif args .from_time and args .to_time :
            print (f"\n[*] Searching records in range:")
            print (f"    From: {args.from_time}")
            print (f"    To:   {args.to_time}")
            search_start =time .time ()
            matching_records =find_records_by_date_range (redis ,args .from_time ,args .to_time )
            search_time =(time .time ()-search_start )*1000 

            if not matching_records :
                print (f"[!] No records found in date range")
                return 

            print (f"[OK] Found {len(matching_records)} records in {search_time:.2f}ms")

            unique_blocks =sorted (set (rec ['block_id']for rec in matching_records ))
            max_block =max (unique_blocks )

            print (f"\n[*] Step 1: Verifying hash chain (genesis -> block {max_block})...")
            chain_start =time .time ()
            chain_valid ,chain_result =verify_chain_to_block (redis ,max_block )
            chain_time =(time .time ()-chain_start )*1000 

            if not chain_valid :
                print (f"[FAIL] Chain verification FAILED: {chain_result.get('error', 'Unknown')}")
                return 

            print (f"[OK] Chain valid: {chain_result.get('blocks_verified', 0)} blocks verified in {chain_time:.2f}ms")

            print (f"\n{'-' * 90}")
            print (f"{'Block':>6} {'Idx':>5} {'PID':>8} {'Energy (J)':>12} {'Power (W)':>12} {'VM':>10} {'Timestamp':>22}")
            print (f"{'-' * 90}")

            for rec in matching_records [:20 ]:
                r =rec ['record']
                print (f"{rec['block_id']:>6} {rec['record_index']:>5} {r['pid']:>8} {r['energy']:>12} {r['power']:>12} {r['vm_name']:>10} {r['timestamp']:>22}")

            if len (matching_records )>20 :
                print (f"    ... and {len(matching_records) - 20} more records")

            print (f"{'-' * 90}")

            use_collective =not args .individual 
            if use_collective :
                print (f"\n[*] Step 2: COLLECTIVE verification - rebuilding Merkle trees...")
                print (f"    Method: O(n) tree rebuild per block (more efficient for batch verification)")
                print (f"    Blocks to process: {len(unique_blocks)}")
            else :
                print (f"\n[*] Step 2: INDIVIDUAL verification - O(log n) Merkle proofs per record...")
                print (f"    Method: Cached O(log n) proofs (less efficient for batch)")
                print (f"    Blocks to cache: {len(unique_blocks)}")

            verified_count ,failed_count ,failed_records ,verify_time =verify_records_batch (redis ,matching_records ,use_collective =use_collective )
            all_valid =(failed_count ==0 )
            total_time =search_time +chain_time +verify_time 

            mode_str ="collective"if use_collective else "individual"
            print (f"\n{'=' * 90}")
            print (f"[{'OK' if all_valid else 'FAIL'}] FULL DATE RANGE VERIFICATION ({mode_str.upper()}): {'ALL VALID' if all_valid else 'SOME INVALID'}")
            print (f"{'=' * 90}")
            print (f"    Date range:       {args.from_time} -> {args.to_time}")
            print (f"    Blocks involved:  {len(unique_blocks)} (IDs: {', '.join(map(str, unique_blocks))})")
            print (f"    Records found:    {len(matching_records)}")
            print (f"    Records verified: {verified_count}")
            print (f"\n    === TIMING ===")
            print (f"    Search time:      {search_time:.2f}ms")
            print (f"    Chain verify:     {chain_time:.2f}ms ({chain_result.get('blocks_verified', 0)} blocks)")
            if use_collective :
                print (f"    Collective verify:{verify_time:.2f}ms ({len(unique_blocks)} trees rebuilt)")
            else :
                print (f"    Individual verify:{verify_time:.2f}ms ({len(matching_records)} proofs)")
            print (f"    TOTAL:            {total_time:.2f}ms")
            print (f"    Avg per record:   {verify_time/len(matching_records):.3f}ms")
            print (f"{'=' * 90}")

            if failed_records :
                print (f"\n[!] Failed records:")
                for block_id ,idx ,error in failed_records :
                    print (f"    Block {block_id}, Record {idx}: {error}")

        elif args .date :
            print (f"\n[*] Searching records for date: {args.date}")
            search_start =time .time ()
            matching_records =find_records_by_date (redis ,args .date )
            search_time =(time .time ()-search_start )*1000 

            if not matching_records :
                print (f"[!] No records found for date {args.date}")
                return 

            print (f"[OK] Found {len(matching_records)} records in {search_time:.2f}ms")
            print (f"\n{'-' * 70}")
            print (f"{'Block':>6} {'Idx':>5} {'PID':>8} {'Energy (J)':>12} {'Power (W)':>10} {'VM':>12}")
            print (f"{'-' * 70}")

            for rec in matching_records [:20 ]:
                r =rec ['record']
                print (f"{rec['block_id']:>6} {rec['record_index']:>5} {r['pid']:>8} {r['energy']:>12} {r['power']:>10} {r['vm_name']:>12}")

            if len (matching_records )>20 :
                print (f"    ... and {len(matching_records) - 20} more records")

            print (f"{'-' * 70}")

            unique_blocks =sorted (set (rec ['block_id']for rec in matching_records ))

            print (f"\n[*] Verifying {len(matching_records)} records with O(log n) Merkle proofs...")
            print (f"    (Caching merkle nodes per block - {len(unique_blocks)} blocks to fetch)")

            verified_count ,failed_count ,failed_records ,verify_time =verify_records_batch (redis ,matching_records )
            all_valid =(failed_count ==0 )

            print (f"\n{'=' * 70}")
            print (f"[{'OK' if all_valid else 'FAIL'}] Date Query Verification: {'ALL VALID' if all_valid else 'SOME INVALID'}")
            print (f"    Records found:    {len(matching_records)}")
            print (f"    Records verified: {verified_count}")
            print (f"    Search time:      {search_time:.2f}ms")
            print (f"    Verify time:      {verify_time:.2f}ms")
            print (f"    Avg per record:   {verify_time/len(matching_records):.3f}ms")
            print (f"{'=' * 70}")

            if failed_records :
                print (f"\n[!] Failed records:")
                for block_id ,idx ,error in failed_records :
                    print (f"    Block {block_id}, Record {idx}: {error}")

        elif args .block is not None :
            print (f"\n[*] Verifying block {args.block} (O(n) full tree rebuild)...")
            is_valid ,details =verify_block (redis ,args .block )
            print_verification_result (is_valid ,details )

        elif getattr (args ,'from_index',None )is not None and getattr (args ,'to_index',None )is not None :

            from_idx =args .from_index 
            to_idx =args .to_index 

            print (f"\n[*] Range verification: index {from_idx} -> {to_idx}")
            print (f"    Mode: NO CACHING (each record verified independently)")
            print (f"    Records to verify: {to_idx - from_idx + 1}")
            print (f"\n{'-' * 90}")
            print (f"{'Index':>8} {'Block':>6} {'Rec':>5} {'Chain':>10} {'Merkle':>10} {'Total':>10} {'Status':>8}")
            print (f"{'-' * 90}")

            chain_times =[]
            merkle_times =[]
            total_times =[]
            valid_count =0 
            invalid_count =0 

            for idx in range (from_idx ,to_idx +1 ):

                block_id ,record_idx ,total_records =find_block_for_index (redis ,idx )

                if block_id <0 :
                    print (f"{idx:>8} {'N/A':>6} {'N/A':>5} {'N/A':>10} {'N/A':>10} {'N/A':>10} {'SKIP':>8}")
                    continue 

                is_valid ,details =verify_record_full (redis ,block_id ,record_idx )

                timing =details .get ('timing',{})
                chain_ms =timing .get ('chain_ms',0 )
                merkle_ms =timing .get ('merkle_ms',0 )
                total_ms =timing .get ('total_ms',0 )

                chain_times .append (chain_ms )
                merkle_times .append (merkle_ms )
                total_times .append (total_ms )

                status ="OK"if is_valid else "FAIL"
                if is_valid :
                    valid_count +=1 
                else :
                    invalid_count +=1 

                print (f"{idx:>8} {block_id:>6} {record_idx:>5} {chain_ms:>9.2f}ms {merkle_ms:>9.2f}ms {total_ms:>9.2f}ms {status:>8}")

            print (f"{'-' * 90}")

            if total_times :
                print (f"\n{'=' * 90}")
                print (f"RANGE VERIFICATION SUMMARY")
                print (f"{'=' * 90}")
                print (f"    Records verified: {len(total_times)}")
                print (f"    Valid: {valid_count}, Invalid: {invalid_count}")
                print (f"\n    === TIMING STATISTICS (no caching) ===")
                print (f"")
                print (f"    {'Metric':<12} {'Chain (ms)':<15} {'Merkle (ms)':<15} {'Total (ms)':<15}")
                print (f"    {'-' * 57}")
                print (f"    {'Min':<12} {min(chain_times):<15.3f} {min(merkle_times):<15.3f} {min(total_times):<15.3f}")
                print (f"    {'Max':<12} {max(chain_times):<15.3f} {max(merkle_times):<15.3f} {max(total_times):<15.3f}")
                print (f"    {'Average':<12} {sum(chain_times)/len(chain_times):<15.3f} {sum(merkle_times)/len(merkle_times):<15.3f} {sum(total_times)/len(total_times):<15.3f}")
                print (f"\n    Note: Each record verified independently (fresh Redis calls)")
                print (f"{'=' * 90}")

        elif args .index is not None :

            print (f"\n[*] Finding block for global index {args.index}...")
            find_start =time .time ()
            block_id ,record_idx ,total_records =find_block_for_index (redis ,args .index )
            find_time =(time .time ()-find_start )*1000 

            if block_id <0 :
                print (f"[FAIL] Index {args.index} out of range (total records: {total_records})")
                return 

            print (f"[OK] Index {args.index} -> Block {block_id}, Record {record_idx} (found in {find_time:.2f}ms)")
            print (f"    Total records in database: {total_records}")
            print (f"\n[*] Full verification:")
            print (f"    Step 1: Verify hash chain (genesis -> block {block_id})")
            print (f"    Step 2: Verify O(log n) Merkle proof\n")

            is_valid ,details =verify_record_full (redis ,block_id ,record_idx )
            print_full_verification_result (is_valid ,details )

        elif args .record :

            try :
                block_id ,record_idx =args .record .split (':')
                block_id =int (block_id )
                record_idx =int (record_idx )
            except ValueError :
                print (f"[!] Invalid format. Use: --record BLOCK_ID:RECORD_INDEX (e.g., --record 1:42)")
                return 

            print (f"\n[*] Full verification of record {record_idx} in block {block_id}...")
            print (f"    Step 1: Verify hash chain (genesis -> block {block_id})")
            print (f"    Step 2: Verify O(log n) Merkle proof\n")

            is_valid ,details =verify_record_full (redis ,block_id ,record_idx )
            print_full_verification_result (is_valid ,details )

        elif args .all :
            print ("\n[*] Verifying all blocks...")
            block_keys =sorted (redis .keys ("block:*"),
            key =lambda k :int (k .split (':')[1 ]))

            total_start =time .time ()
            all_valid =True 

            for block_key in block_keys :
                block_id =int (block_key .split (':')[1 ])
                is_valid ,details =verify_block (redis ,block_id )
                print_verification_result (is_valid ,details ,compact =True )
                if not is_valid :
                    all_valid =False 

            total_time =(time .time ()-total_start )*1000 
            print (f"\n{'=' * 70}")
            print (f"[{'OK' if all_valid else 'FAIL'}] All {len(block_keys)} blocks: "
            f"{'VALID' if all_valid else 'SOME INVALID'}")
            print (f"    Total verification time: {total_time:.2f}ms")

        else :

            block_keys =redis .keys ("block:*")
            print (f"\n[*] Found {len(block_keys)} blocks in database")

            if block_keys :
                print ("\n[*] Verifying first block as sample...")
                block_id =min (int (k .split (':')[1 ])for k in block_keys )
                is_valid ,details =verify_block (redis ,block_id )
                print_verification_result (is_valid ,details )

                print ("\nUse --all to verify all blocks")
                print ("Use --chain to verify block chain integrity")

    finally :
        redis .close ()

def print_verification_result (is_valid :bool ,details :Dict [str ,Any ],compact :bool =False ):
    """Print verification result"""
    if "error"in details :
        print (f"[FAIL] Error: {details['error']}")
        return 

    status ="OK"if is_valid else "FAIL"

    if compact :
        timing =details .get ('timing',{})
        print (f"    Block {details['block_id']}: [{status}] "
        f"{details['record_count']} records, "
        f"{timing.get('total_ms', 0):.2f}ms")
    else :
        print (f"\n[{status}] Block {details['block_id']} Verification: {'VALID' if is_valid else 'INVALID'}")
        print (f"    Block number: {details['block_number']}")
        print (f"    VM name: {details['vm_name']}")
        print (f"    Records: {details['record_count']}")
        print (f"    Tree height: {details['tree_height']}")
        print (f"    Stored root:   {details['stored_root']}")
        print (f"    Computed root: {details['computed_root']}")

        timing =details .get ('timing',{})
        print (f"\n    Timing breakdown:")
        print (f"      Fetch records: {timing.get('fetch_ms', 0):.2f}ms")
        print (f"      Parse records: {timing.get('parse_ms', 0):.2f}ms")
        print (f"      Build Merkle:  {timing.get('tree_build_ms', 0):.2f}ms")
        print (f"      TOTAL:         {timing.get('total_ms', 0):.2f}ms")

def print_record_verification_result (is_valid :bool ,details :Dict [str ,Any ]):
    """Print O(log n) record verification result"""
    if "error"in details :
        print (f"[FAIL] Error: {details['error']}")
        return 

    status ="OK"if is_valid else "FAIL"

    print (f"\n[{status}] Record Verification: {'VALID' if is_valid else 'INVALID'}")
    print (f"\n    === O(log n) MERKLE PROOF VERIFICATION ===")
    print (f"    Block ID: {details['block_id']}")
    print (f"    Record index: {details['record_idx']} / {details['record_count'] - 1}")
    print (f"    Tree height: {details['tree_height']} levels")
    print (f"    Proof length: {details['proof_length']} sibling hashes")
    print (f"    {details['complexity']}")

    print (f"\n    Record data:")
    record =details .get ('record_data',{})
    print (f"      PID: {record.get('pid')}")
    print (f"      Energy: {record.get('energy')}")
    print (f"      VM: {record.get('vm_name')}")
    print (f"      Timestamp: {record.get('timestamp')}")

    print (f"\n    Merkle roots:")
    print (f"      Stored:   {details['stored_root']}")
    print (f"      Computed: {details['computed_root']}")

    print (f"\n    Proof path (leaf -> root):")
    for step in details .get ('proof_path',[]):
        direction ="->"if step ['is_left']else "<-"
        print (f"      Level {step['level']}: pos={step['position']} "
        f"{direction} sibling={step['sibling_pos']} "
        f"hash={step['sibling_hash']}")

    timing =details .get ('timing',{})
    print (f"\n    Timing breakdown:")
    print (f"      Fetch 1 record:  {timing.get('fetch_record_ms', 0):.3f}ms")
    print (f"      Merkle proof:    {timing.get('merkle_proof_ms', 0):.3f}ms")
    print (f"      TOTAL:           {timing.get('total_ms', 0):.3f}ms")

    print (f"\n    Comparison vs O(n):")
    print (f"      O(n) would fetch: {details['record_count']} records")
    print (f"      O(log n) fetched: 1 record + {details['proof_length']} hashes")
    print (f"      Data reduction:   {details['record_count'] / (1 + details['proof_length']):.1f}x less data")

def print_full_verification_result (is_valid :bool ,details :Dict [str ,Any ]):
    """Print full verification result (chain + Merkle proof)"""
    if "error"in details :
        print (f"[FAIL] Error: {details['error']}")
        chain_info =details .get ('chain_verification',{})
        if chain_info :
            print (f"    Chain blocks verified: {chain_info.get('blocks_verified', 0)}")
        return 

    status ="OK"if is_valid else "FAIL"
    chain_info =details .get ('chain_verification',{})
    merkle_info =details .get ('merkle_verification',{})
    timing =details .get ('timing',{})

    print (f"{'=' * 70}")
    print (f"[{status}] FULL RECORD VERIFICATION: {'VALID' if is_valid else 'INVALID'}")
    print (f"{'=' * 70}")

    chain_status ="OK"if chain_info .get ('valid')else "FAIL"
    print (f"\n    === STEP 1: HASH CHAIN VERIFICATION ===")
    print (f"    [{chain_status}] Chain: Genesis -> Block {merkle_info.get('block_id', '?')}")
    print (f"    Blocks verified: {chain_info.get('blocks_verified', 0)}")
    print (f"    Time: {chain_info.get('timing_ms', 0):.3f}ms")

    if merkle_info :
        leaf_status ="OK"if merkle_info .get ('leaf_hash_valid')else "FAIL"
        proof_status ="OK"if merkle_info .get ('merkle_proof_valid')else "FAIL"
        merkle_status ="OK"if merkle_info .get ('is_valid')else "FAIL"
        print (f"\n    === STEP 2: O(log n) MERKLE PROOF ===")
        print (f"    [{merkle_status}] Record {merkle_info.get('record_idx', '?')} in Block {merkle_info.get('block_id', '?')}")
        print (f"    [{leaf_status}] Leaf hash: recomputed from data")
        print (f"    [{proof_status}] Merkle proof: leaf -> root")
        print (f"    Tree height: {merkle_info.get('tree_height', 0)} levels")
        print (f"    Proof length: {merkle_info.get('proof_length', 0)} sibling hashes")
        print (f"    {merkle_info.get('complexity', '')}")

        print (f"\n    Record data:")
        record =merkle_info .get ('record_data',{})
        print (f"      PID: {record.get('pid')}")
        print (f"      Energy: {record.get('energy')}")
        print (f"      VM: {record.get('vm_name')}")
        print (f"      Timestamp: {record.get('timestamp')}")

        print (f"\n    Leaf hashes:")
        print (f"      Stored:   {merkle_info.get('stored_leaf', '')}")
        print (f"      Computed: {merkle_info.get('computed_leaf', '')}")

        print (f"\n    Merkle roots:")
        print (f"      Stored:   {merkle_info.get('stored_root', '')}")
        print (f"      Computed: {merkle_info.get('computed_root', '')}")

        print (f"\n    Proof path (leaf -> root):")
        for step in merkle_info .get ('proof_path',[]):
            direction ="->"if step ['is_left']else "<-"
            print (f"      Level {step['level']}: pos={step['position']} "
            f"{direction} sibling={step['sibling_pos']} "
            f"hash={step['sibling_hash']}")

    merkle_timing =merkle_info .get ('timing',{})if merkle_info else {}
    nodes_fetched =merkle_info .get ('nodes_fetched',0 )if merkle_info else 0 

    print (f"\n    === TIMING BREAKDOWN ===")
    print (f"    Chain verification: {timing.get('chain_ms', 0):.3f}ms")
    print (f"    Merkle proof:       {timing.get('merkle_ms', 0):.3f}ms")
    if merkle_timing :
        print (f"      +- Meta fetch:    {merkle_timing.get('meta_fetch_ms', 0):.3f}ms  (HGETALL block)")
        print (f"      +- Record fetch:  {merkle_timing.get('record_fetch_ms', 0):.3f}ms  (LINDEX)")
        print (f"      +- Hash compute:  {merkle_timing.get('hash_compute_ms', 0):.3f}ms  (SHA256 leaf)")
        print (f"      +- Nodes fetch:   {merkle_timing.get('nodes_fetch_ms', 0):.3f}ms  (HMGET {nodes_fetched} nodes)")
        print (f"      +- Proof verify:  {merkle_timing.get('proof_verify_ms', 0):.3f}ms  (O(log n) hashes)")
    print (f"    -----------------------------")
    print (f"    TOTAL:              {timing.get('total_ms', 0):.3f}ms")
    print (f"{'=' * 70}")

if __name__ =="__main__":
    main ()
