# LemonHaze - 2025

import idautils
import idaapi
import idc
import ida_kernwin
import ida_hexrays
import idc

from .config import *
from llama_index.core import Document, GPTVectorStoreIndex, StorageContext, load_index_from_storage
from llama_index.core.settings import Settings
from llama_index.llms.ollama import Ollama
from llama_index.embeddings.ollama import OllamaEmbedding

import hashlib
import json
import os

ACTION_LLM_INDEX = "lemonutils:llm_index"
ACTION_LLM_QUERY = "lemonutils:llm_query"

def extract_functions():
    functions = []
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        disassembly = []
        
        for head in idautils.Heads(idc.get_func_attr(func_ea, idc.FUNCATTR_START), 
                                   idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
            disassembly.append(idc.GetDisasm(head))
        
        if llm_util_include_pseudo:
            pseudocode = idaapi.decompile(func_ea)    
            
        function_data = {
            "name": func_name,
            "start_addr": hex(func_ea),
            "disassembly": "\n".join(disassembly),
            "pseudocode": pseudocode if llm_util_include_pseudo else ""
        }
        functions.append(function_data)
    
    return functions

def save_functions_to_json(filepath="functions.json"):
    functions = extract_functions()
    with open(filepath, "w") as f:
        json.dump(functions, f, indent=4)

def create_index(data_path="functions.json"):
    with open(data_path, "r") as f:
        functions = json.load(f)
    
    documents = []
    for func in functions:
        text = f"Function: {func['name']}\nAddress: {func['start_addr']}\n\nDisassembly:\n{func['disassembly']}\n\n"
        if llm_util_include_pseudo:
            text += f"Pseudocode:\n{func['pseudocode']}\n\n"
        documents.append(Document(text=text, metadata={"function_name": func["name"]}))

    index = GPTVectorStoreIndex.from_documents(documents)
    index.storage_context.persist(persist_dir="function_index")
    return index

def query_index(index, query):
    response = index.as_query_engine().query(query)
    return response

def calculate_hash(data):
    json_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(json_bytes).hexdigest()
    
def ensure_functions_are_saved(filepath="functions.json"):
    if not os.path.exists(filepath):
        save_functions_to_json(filepath)
        return

    with open(filepath, "r") as f:
        existing_functions = json.load(f)
    current_functions = extract_functions()
    existing_hash = calculate_hash(existing_functions)
    current_hash = calculate_hash(current_functions)

    if existing_hash != current_hash:
        save_functions_to_json(filepath)
        
class IndexFunctionsHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        #ensure_functions_are_saved()                   #@todo: fixme
        create_index()
        print("Indexing completed.")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class SearchFunctionsHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        query = idaapi.ask_str("", 0, "Enter your search query")
        if query:
            print(f"Search query: {query}")
            storage_context = StorageContext.from_defaults(persist_dir="function_index")
            index = load_index_from_storage(storage_context)
            response = query_index(index, query)
            print("Query Result:", response)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def register_llm_util():
    llm = Ollama(model=reasoning_model_name, temperature=0)
    embed_model = OllamaEmbedding(
                        model_name=embed_model_name, 
                        base_url="http://localhost:11434", 
                        ollama_additional_kwargs={"mirostat": 0})
    Settings.llm = llm
    Settings.embed_model = embed_model 

    idaapi.register_action(
        idaapi.action_desc_t(
            ACTION_LLM_INDEX,
            "Index",
            IndexFunctionsHandler(),
            "Shift-I"
    ))
    idaapi.register_action(
        idaapi.action_desc_t(
            ACTION_LLM_QUERY,
            "Query",
            SearchFunctionsHandler(),
            "Shift-S"
    ))

    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/LLM/",
        ACTION_LLM_INDEX,  
        ida_kernwin.SETMENU_APP
    )    
    ida_kernwin.attach_action_to_menu(
        "Edit/LemonJuice/LLM/",
        ACTION_LLM_QUERY,  
        ida_kernwin.SETMENU_APP
    )
    
def unregister_llm_util():
    ida_kernwin.unregister_action(ACTION_LLM_INDEX)
    ida_kernwin.unregister_action(ACTION_LLM_QUERY)