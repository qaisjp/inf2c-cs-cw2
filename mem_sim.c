/***************************************************************************
 * *    Inf2C-CS Coursework 2: TLB and Cache Simulation
 * *    
 * *    Instructor: Boris Grot
 * *
 * *    TA: Priyank Faldu
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <math.h>
/* Do not add any more header files */

/*
 * Various structures
 */
typedef enum {tlb_only, cache_only, tlb_cache} hierarchy_t;
typedef enum {instruction, data} access_t;
const char* get_hierarchy_type(uint32_t t) {
    switch(t) {
        case tlb_only: return "tlb_only";
        case cache_only: return "cache-only";
        case tlb_cache: return "tlb+cache";
        default: assert(0); return "";
    };
    return "";
}

typedef struct {
    uint32_t address;
    access_t accesstype;
} mem_access_t;

// YOU UPDATE
// These are statistics for the cache and TLB and should be maintained by you.
typedef struct {
    uint32_t tlb_data_hits;
    uint32_t tlb_data_misses;
    uint32_t tlb_instruction_hits;
    uint32_t tlb_instruction_misses;
    uint32_t cache_data_hits;
    uint32_t cache_data_misses;
    uint32_t cache_instruction_hits;
    uint32_t cache_instruction_misses;
} result_t;

// YOU USE
/*
 * Parameters for TLB and cache that will be populated by the provided code skeleton.
 */
hierarchy_t hierarchy_type = tlb_cache; // mode script is currently running in
uint32_t number_of_tlb_entries = 0; // number of entries the tlb should have
uint32_t page_size = 0; // size of the pagefile
uint32_t number_of_cache_blocks = 0; // number of blocks
uint32_t cache_block_size = 0; // bytes each block has
uint32_t num_page_table_accesses = 0; // automatically done

// YOU UPDATE
/*
 * Each of the variables (subject to hierarchy_type) below must be populated by you.
 */
uint32_t g_total_num_virtual_pages = 0;
uint32_t g_num_tlb_tag_bits = 0;
uint32_t g_tlb_offset_bits = 0;
uint32_t g_num_cache_tag_bits = 0; // bits to store a tag
uint32_t g_cache_offset_bits= 0; // bits to store an offset
result_t g_result;


/* Reads a memory access from the trace file and returns
 * 1) access type (instruction or data access)
 * 2) 32-bit virtual memory address
 */
mem_access_t read_transaction(FILE *ptr_file) {
    char buf[1002];
    char* token = NULL;
    char* string = buf;
    mem_access_t access;

    if (fgets(buf, 1000, ptr_file)!=NULL) {

        /* Get the access type */
        token = strsep(&string, " \n");        
        if (strcmp(token,"I") == 0) {
            access.accesstype = instruction;
        } else if (strcmp(token,"D") == 0) {
            access.accesstype = data;
        } else {
            printf("Unkown access type\n");
            exit(-1);
        }

        /* Get the address */        
        token = strsep(&string, " \n");
        access.address = (uint32_t)strtol(token, NULL, 16);

        return access;
    }

    /* If there are no more entries in the file return an address 0 */
    access.address = 0;
    return access;
}

/* 
 * Call this function to get the physical page number for a given virtual number.
 * Note that this function takes virtual page number as an argument and not the whole virtual address.
 * Also note that this is just a dummy function for mimicing translation. Real systems maintains multi-level page tables.
 */
uint32_t dummy_translate_virtual_page_num(uint32_t virtual_page_num) {
    uint32_t physical_page_num = virtual_page_num ^ 0xFFFFFFFF;
    num_page_table_accesses++;
    if ( page_size == 256 ) {
        physical_page_num = physical_page_num & 0x00FFF0FF;
    } else {
        assert(page_size == 4096);
        physical_page_num = physical_page_num & 0x000FFF0F;
    }
    return physical_page_num;
}

void print_statistics(uint32_t num_virtual_pages, uint32_t num_tlb_tag_bits, uint32_t tlb_offset_bits, uint32_t num_cache_tag_bits, uint32_t cache_offset_bits, result_t* r) {
    /* Do Not Modify This Function */

    printf("NumPageTableAccesses:%u\n", num_page_table_accesses);
    printf("TotalVirtualPages:%u\n", num_virtual_pages);

    // If tlb or (tlb+cache)
    if ( hierarchy_type != cache_only ) {
        printf("TLBTagBits:%u\n", num_tlb_tag_bits);
        printf("TLBOffsetBits:%u\n", tlb_offset_bits);
        uint32_t tlb_total_hits = r->tlb_data_hits + r->tlb_instruction_hits; 
        uint32_t tlb_total_misses = r->tlb_data_misses + r->tlb_instruction_misses; 
        printf("TLB:Accesses:%u\n", tlb_total_hits + tlb_total_misses);
        printf("TLB:data-hits:%u, data-misses:%u, inst-hits:%u, inst-misses:%u\n", r->tlb_data_hits, r->tlb_data_misses, r->tlb_instruction_hits, r->tlb_instruction_misses);
        printf("TLB:total-hit-rate:%2.2f%%\n", tlb_total_hits / (float)(tlb_total_hits + tlb_total_misses) * 100.0); 
    }

    // If cache or (tlb+cache)
    if ( hierarchy_type != tlb_only ) {
        printf("CacheTagBits:%u\n", num_cache_tag_bits); 
        printf("CacheOffsetBits:%u\n", cache_offset_bits); 
        uint32_t cache_total_hits = r->cache_data_hits + r->cache_instruction_hits; 
        uint32_t cache_total_misses = r->cache_data_misses + r->cache_instruction_misses; 
        printf("Cache:data-hits:%u, data-misses:%u, inst-hits:%u, inst-misses:%u\n", r->cache_data_hits, r->cache_data_misses, r->cache_instruction_hits, r->cache_instruction_misses);
        printf("Cache:total-hit-rate:%2.2f%%\n", cache_total_hits / (float)(cache_total_hits + cache_total_misses) * 100.0); 
    }
}

/*
 *
 * TODO: Add any global variables and/or functions here as you wish.
 *
 */

// Declare own boolean type, because
// including <stdbool.h> is not allowed :(
typedef uint8_t bool;
#define true 1
#define false 0

// Define own print so we can turn off debug messages later
bool debug = true;
#define print(...) if (debug) { printf(__VA_ARGS__); }

// Number of bits required to represent an index
// of the cache. This number of bits is used
// to derive the index from the address.
uint32_t g_cache_index_bits;

// Other stuff
bool g_use_tlb;
bool g_use_cache;

// Type for an individual cache_block,
// (direct mapped)
typedef struct {
    bool valid;
    uint32_t tag;
} cache_block_t;

// Cache
cache_block_t* g_cache;

// tlb entry
typedef struct {
    bool valid;

    // consider adding this field if you intend to back this cache by a store
    // bool dirty;

    uint32_t tag;
    uint32_t ppn; // physical page number
    uint32_t lru_id;
} tlb_entry_t;

// tlb cache
tlb_entry_t* g_tlb;

// Confirmed. Gets the cache block index of the address.
uint32_t get_address_cache_block_index(uint32_t address) {
    // Push off the bunch on the left we don't want
    // and come back to the middle.. then push off the right hand side
    uint32_t raw_index = (address << g_num_cache_tag_bits) >> (g_num_cache_tag_bits + g_cache_offset_bits);

    return raw_index % number_of_cache_blocks;
}

// Confirmed.
uint32_t get_address_cache_offset(uint32_t address) {
    uint32_t lhs = (g_num_cache_tag_bits + g_cache_index_bits);
    return (address << lhs) >> lhs;
}

// Confirmed.
uint32_t get_address_cache_tag(uint32_t address) {
    // address is of this form:
    // [TAG][INDEX][OFFSET]
    //   ^     ^      ^
    //   |     |      |
    //   |     |   g_cache_offset_bits
    //   |   g_cache_index_bits
    //  g_num_cache_tag_bits
    //
    // We want tag.
    // So shift right (index + offset) bits, and return that.
    return address >> (g_cache_index_bits + g_cache_offset_bits);
}

void initialise() {
    print("Initialising..\n");

    g_use_tlb = hierarchy_type != cache_only;
    g_use_cache = hierarchy_type != tlb_only;

    // Similar thing for page_size
    g_tlb_offset_bits = log2(page_size);
    g_num_tlb_tag_bits = 32 - g_tlb_offset_bits;

    // max number representable in the bit count for page_number
    g_total_num_virtual_pages = 1 << g_num_tlb_tag_bits;

    if (g_use_tlb) {
        // size of the tlb array
        //
        uint32_t tlb_size = sizeof(tlb_entry_t) * number_of_tlb_entries;
        
        // allocate and error handle
        g_tlb = malloc(tlb_size);
        if (g_tlb == NULL) {
            printf("ERROR: out of memory!");
            exit(-1);
        }

        // zero everything in the cache (each block as well)
        memset(g_tlb, 0, tlb_size);
    }

    if (!g_use_cache) {
        return;
    }

    // Each "block number" is represented in
    // n = log2(block_count) bits...
    // and each "block number" is actually the **index**.
    g_cache_index_bits = log2(number_of_cache_blocks);
    print("CacheIndexBits: %d\n", g_cache_index_bits);

    // offsetCount = cache_block_size; because size is in bytes, addresses use 1 byte each
    // g_cache_offset_bits = log2(offsetCount); // bits required to store the count
    g_cache_offset_bits = log2(cache_block_size);

    // We are told in the spec that an address is always 32 bits.
    // We have determined how many of those bits are for finding the
    // index to key a block. (g_cache_index_bits)
    // We have also determined how many of those bits are needed to find
    // the offset within a particular block. (g_cache_offset_bits)
    // The rest of the bits can be used to derive our tag, so we've
    // counted down and we can store it in `g_num_cache_tag_bits`
    g_num_cache_tag_bits = 32 - g_cache_index_bits - g_cache_offset_bits;

    // calculate size to allocate
    uint32_t cache_size = sizeof(cache_block_t) * number_of_cache_blocks;

    // allocate and error handle
    g_cache = malloc(cache_size);
    if (g_cache == NULL) {
        printf("ERROR: out of memory!");
        exit(-1);
    }

    // zero everything in the cache (each block as well)
    memset(g_cache, 0, cache_size);
}

void cleanup() {
    print("Cleaning up...\n");

    if (g_use_cache) {
        free(g_cache);
    }

    if (g_use_tlb) {
        free(g_tlb);
    }
}

// Generates a bit sequence of `num` ones.
// i.e, generate_ones(8) makes 11111111 (eight ones in binary, 0xFF)
uint32_t generate_ones(uint32_t num) {
    return (1 << num) - 1;
}

void get_physical_address_tlb(uint32_t virt_page_number, uint32_t* phys_page_number, bool* hit) {
    // 1. Check if we have an entry, and whilst we're here
    //    also find the least recently used entry (if we need it)
    //
    tlb_entry_t* it = g_tlb; // "iterator"
    uint32_t index = 0;

    tlb_entry_t* found; // the pointer to the entry we've found
    tlb_entry_t* lru_entry; // the entry we would remove

    // Initialise hit to false.
    *hit = false;

    // while we haven't reached the end of the array
    while (index < number_of_tlb_entries) {
        // if this is valid, and the tag matches..
        if (it->valid && it->tag == virt_page_number) {
            *hit = true; // notify caller it was a hit
            found = it; // found it! haha
            // print("Found.\n");
        } else if (it->lru_id == 0) {
            // We zero g_tlb when we malloc it,
            // so we can just keep taking the empty ones
            // even if we haven't consumed the entire buffer.
            // (i.e even if they are not valid)
            lru_entry = it;

            // The above will run twice in all cases except one.
            // That's okay. It won't hurt.
            if (*hit) {
                break;
            }

        }

        // next item in the array...
        index += 1;;
        it += 1;
    }

    // print("Finished 1 \n");

    // 2a. If we have an entry, we need to decrement all the entries
    //     with a greater lru_id than the one we found. Then we can
    //     make our lru_id the greatest lru_id.
    if (*hit) {
        it = g_tlb; // reset our iterator
        index = 0;

        while (index < number_of_tlb_entries) {
            // if this lru_id is greater than the one we found
            if (it->lru_id > found->lru_id) {
                // decrement our lru_id
                it->lru_id -= 1;
            }

            index += 1;
            it++;
        }

        // set our lru_id to largest "index"
        found->lru_id = number_of_tlb_entries;

        // update physical page number for caller
        *phys_page_number = found->ppn;

        // print("Exited.\n");
        return;
    }

    // (we know we don't have an entry now)

    // 2b. If we don't have an entry, we need to decrement ALL the entries;
    //     except WE DON'T decrement the entry with lru_id 0).
    //
    //     Then we query for the translated page number, and replace the LEAST
    //     recently used entry with the greatest lru_id, as well as update its tag.

    it = g_tlb; // reset our iterator
    index = 0;

    while (index < number_of_tlb_entries) {
        // again, we don't need to worry about non-valid ones here...
        if (it->lru_id != 0) {
            it->lru_id -= 1;
        }

        index += 1;
        it += 1;
    }

    lru_entry->valid = true;
    lru_entry->tag = virt_page_number;
    lru_entry->ppn = dummy_translate_virtual_page_num(virt_page_number);
    lru_entry->lru_id = number_of_tlb_entries;

    *phys_page_number = lru_entry->ppn;
    // print("Hit! \n");

    return;
}

void increment_by_accesstype(access_t type, uint32_t* data_counter, uint32_t* instruction_counter) {
    if (type == data) {
        *data_counter += 1;
    } else if (type == instruction) {
        *instruction_counter += 1;
    }
}

// Translate virtual access to physical access
void translate_access_physical(mem_access_t* access) {
    uint32_t address = access->address;

    uint32_t virt_page_number = address >> g_tlb_offset_bits;
    uint32_t page_offset = address & generate_ones(g_tlb_offset_bits);
    uint32_t phys_page_number;

    if (g_use_tlb) {
        bool ok = false;
        get_physical_address_tlb(virt_page_number, &phys_page_number, &ok);

        if (ok) {
            increment_by_accesstype(
                access->accesstype,
                &g_result.tlb_data_hits,
                &g_result.tlb_instruction_hits
            );
        } else {
            increment_by_accesstype(
                access->accesstype,
                &g_result.tlb_data_misses,
                &g_result.tlb_instruction_misses
            );
        }
    } else {
        phys_page_number = dummy_translate_virtual_page_num(virt_page_number);
    }
    
    // concat the page offset (10 bits) onto the phys_page number
    access->address = (phys_page_number << g_tlb_offset_bits) + page_offset;
}

void process_mem_access(mem_access_t access) {
    // Translate virtual access to physical access
    translate_access_physical(&access);

    // If we're not using the cache, stop right there!
    if (!g_use_cache) {
        return;
    }

    uint32_t address = access.address; // virtual address here

    uint32_t index = get_address_cache_block_index(address);
    cache_block_t* block = &g_cache[index];

    uint32_t tag = get_address_cache_tag(access.address);
    bool matched_tag = block->tag == tag;
    bool valid = block->valid;

    if (valid && matched_tag) {
        // print("HIT!!\n");
        increment_by_accesstype(
            access.accesstype,
            &g_result.cache_data_hits,
            &g_result.cache_instruction_hits
        );
    } else {
        block->tag = tag;
        block->valid = true;
        // print("MISS!!\n");

        // print("%x -> [tag: %d, block_index: %d, offset: %d]\n",
        //     access.address,
        //     tag,
        //     index,
        //     g_cache_offset_bits
        // );

        increment_by_accesstype(
            access.accesstype,
            &g_result.cache_data_misses,
            &g_result.cache_instruction_misses
        );
    }

    // printf("Processing %d %s\n", access.address, get_access_type(access.accesstype));
    // print("Cache block o/zf %d (%x) is %d\n", access.address, access.address, get_address_cache_block_index(access.address));
}

int main(int argc, char** argv) {

    /*
     * 
     * Read command-line parameters and initialize configuration variables.
     *
     */
    int improper_args = 0;
    char file[10000];
    if ( argc < 2 ) {
        improper_args = 1;
        printf("Usage: ./mem_sim [hierarchy_type: tlb-only cache-only tlb+cache] [number_of_tlb_entries: 8/16] [page_size: 256/4096] [number_of_cache_blocks: 256/2048] [cache_block_size: 32/64] mem_trace.txt\n");
    } else  {
        /* argv[0] is program name, parameters start with argv[1] */
        if ( strcmp(argv[1], "tlb-only") == 0 ) {
            if ( argc != 5 ) { 
                improper_args = 1;
                printf("Usage: ./mem_sim tlb-only [number_of_tlb_entries: 8/16] [page_size: 256/4096] mem_trace.txt\n");
            } else {
                hierarchy_type = tlb_only;
                number_of_tlb_entries = atoi(argv[2]); 
                page_size = atoi(argv[3]);
                strcpy(file, argv[4]);
            }
        } else if ( strcmp(argv[1], "cache-only") == 0 ) {
            if ( argc != 6 ) { 
                improper_args = 1;
                printf("Usage: ./mem_sim cache-only [page_size: 256/4096] [number_of_cache_blocks: 256/2048] [cache_block_size: 32/64] mem_trace.txt\n");
            } else {
                hierarchy_type = cache_only;
                page_size = atoi(argv[2]);
                number_of_cache_blocks = atoi(argv[3]);
                cache_block_size = atoi(argv[4]);
                strcpy(file, argv[5]);
            }
        } else if ( strcmp(argv[1], "tlb+cache") == 0 ) {
            if ( argc != 7 ) { 
                improper_args = 1;
                printf("Usage: ./mem_sim tlb+cache [number_of_tlb_entries: 8/16] [page_size: 256/4096] [number_of_cache_blocks: 256/2048] [cache_block_size: 32/64] mem_trace.txt\n");
            } else {
                hierarchy_type = tlb_cache;
                number_of_tlb_entries = atoi(argv[2]); 
                page_size = atoi(argv[3]);
                number_of_cache_blocks = atoi(argv[4]);
                cache_block_size = atoi(argv[5]);
                strcpy(file, argv[6]);
            }
        } else {
            printf("Unsupported hierarchy type: %s\n", argv[1]);
            improper_args = 1;
        }
    }
    if ( improper_args ) {
        exit(-1);
    }
    assert(page_size == 256 || page_size == 4096);
    if ( hierarchy_type != cache_only) {
        assert(number_of_tlb_entries == 8 || number_of_tlb_entries == 16);
    }
    if ( hierarchy_type != tlb_only) {
        assert(number_of_cache_blocks == 256 || number_of_cache_blocks == 2048);
        assert(cache_block_size == 32 || cache_block_size == 64);
    }

    printf("input:trace_file: %s\n", file);
    printf("input:hierarchy_type: %s\n", get_hierarchy_type(hierarchy_type));
    printf("input:number_of_tlb_entries: %u\n", number_of_tlb_entries);
    printf("input:page_size: %u\n", page_size);
    printf("input:number_of_cache_blocks: %u\n", number_of_cache_blocks);
    printf("input:cache_block_size: %u\n", cache_block_size);
    printf("\n");
    
    /* Open the file mem_trace.txt to read memory accesses */
    FILE *ptr_file;
    ptr_file =fopen(file,"r");
    if (!ptr_file) {
        printf("Unable to open the trace file: %s\n", file);
        exit(-1);
    }

    /* result structure is initialized for you. */
    memset(&g_result, 0, sizeof(result_t));

    /* Do not delete any of the lines below.
     * Use the following snippet and add your code to finish the task. */

    /* You may want to setup your TLB and/or Cache structure here. */
    initialise();

    mem_access_t access;
    /* Loop until the whole trace file has been read. */
    while(1) {
        access = read_transaction(ptr_file);
        // If no transactions left, break out of loop.
        if (access.address == 0)
            break;
        /* Add your code here */
        /* Feed the address to your TLB and/or Cache simulator and collect statistics. */
        process_mem_access(access);
    }

    cleanup();

    /* Do not modify code below. */
    /* Make sure that all the parameters are appropriately populated. */
    print_statistics(g_total_num_virtual_pages, g_num_tlb_tag_bits, g_tlb_offset_bits, g_num_cache_tag_bits, g_cache_offset_bits, &g_result);

    /* Close the trace file. */
    fclose(ptr_file);
    return 0;
}
