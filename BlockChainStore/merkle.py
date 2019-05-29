# Created on Tue April 16 14:55:21 2019
# @author: Rivindu Wijayarathna


import hashlib

    
def hasher(hash_input): 
    x = hashlib.sha256(hash_input).hexdigest()
    return x
 
def gen_merkle_tree_hash(blockchain):    
    bc_queue = [blockchain[i] for i in range(len(blockchain))]
     
    num_blocks = len(bc_queue)  
    if num_blocks % 2 == 1:
        bc_queue.append(bc_queue[-1])
     
    while len(bc_queue) > 1:
        block1 = bc_queue.pop(0)
        #print("block1", block1)
        block2 = bc_queue.pop(0)
        #print ("block2", block2)
        bc_queue.append(hasher(block1 + block2))
    return bc_queue[0]

# if __name__ == '__main__':
#     list_tt = ['83c4e82b33bd947f7ef6ee425e5a5d62ad52dc21c6ca6243f5891258eaf4ee6a','83c4e82b33bd947f7ef6ee425e5a5d62ad52dc21c6ca6243f5891258eaf4ee6b','83c4e82b33bd947f7ef6ee425e5a5d62ad52dc21c6ca6243f5891258eaf4ee6c','83c4e82b33bd947f7ef6ee425e5a5d62ad52dc21c6ca6243f5891258eaf4ee6d','83c4e82b33bd947f7ef6ee425e5a5d62ad52dc21c6ca6243f5891258eaf4ee6f']
#     merkele_root = gen_merkle_tree_hash(list_tt)
#     print(merkele_root)