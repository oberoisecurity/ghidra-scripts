# Given a text file with one or more function names, recursively decompiles each function including all enums, structs, and functions it calls. 
# Each function  should be in hex and on it's own line. Output is written to decomp.c. 
#@author Paramjot (PJ) Oberoi, Oberoi Security Solutions
#@category Data

from ghidra.app.decompiler import DecompInterface

visited_funcs = {}
visited_types = {}
visited_structs = {}
visited_enums = {}

current_funcs = []
current_types = []

monitor = getMonitor()
ifc = DecompInterface()
ifc.openProgram(getCurrentProgram())
out_file = open("decomp.c", "w")

#
# data collection
#

# given a function, record all functions it calls
# as well as all types (local or parameters) it uses
def visit_func(func):

	# check if have already seen this function
	if func in visited_funcs:
		return

	visited_funcs[func] = func

	# find all functions this function calls
	called_funcs = func.getCalledFunctions(monitor)
	for called_func in called_funcs:
		current_funcs.append(called_func)

	# find all types used by this function
	variables = func.getAllVariables()
	for variable in variables:
		datatype = variable.getDataType()
		current_types.append(datatype)

# given a datatype, recurse on structures
# record enums as well
def visit_types(datatype):

	# check if have already seen this function
	if datatype in visited_types:
		return

	visited_types[datatype] = datatype

	# nothing to do for enums except print them separately
	if isinstance(datatype, ghidra.program.database.data.EnumDB):
		visited_enums[datatype] = datatype
		return

	# if pointer or array, get the base type and recurse
	if isinstance(datatype, (ghidra.program.database.data.PointerDB, ghidra.program.database.data.ArrayDB)):
		current_types.append(datatype.getDataType())
		return

	# for structures recurse on each element
	if isinstance(datatype, ghidra.program.database.data.StructureDB):

		visited_structs[datatype] = datatype

		components = datatype.getComponents()
		for component in components:
			current_types.append(component.getDataType())

		return

#
# output
#

# print found enums
def print_enums():

	out_file.write("//\n")
	out_file.write("// enums\n")
	out_file.write("//\n\n")

	for enum in visited_enums:

		out_file.write("typedef enum\n")
		out_file.write("{\n")


		enum_names = enum.getNames()

		for enum_name in enum_names:

			comment = enum.getComment(enum_name)
			if comment:
				comment = " // " + comment
			else:
				comment = ""

			out_file.write("\t" + enum_name + " = " + str(enum.getValue(enum_name)) + "," + comment + "\n")

		out_file.write("}" + enum.getDisplayName() + ";" + "\n\n")

# print found structures
def print_structs():

	out_file.write("//\n")
	out_file.write("// structs\n")
	out_file.write("//\n\n")

	sorted_types = sorted(visited_types)
	for datatype in sorted_types:

		# we only are about structs
		if not isinstance(datatype, ghidra.program.database.data.StructureDB):
			continue

		out_file.write("struct " + datatype.getDisplayName() + "\n")
		out_file.write("{\n")
		for member in datatype.getComponents():

			comment = member.getComment()
			if comment:
				comment = " // " + comment
			else:
				comment = ""

			out_file.write("\t" + member.getDataType().getDisplayName() + " " + str(member.getFieldName()) + ";" + comment + "\n")

		out_file.write("};\n")
		out_file.write("typedef " + datatype.getDisplayName() + " " + datatype.getDisplayName() + ";\n\n")


# decompile and print the function
# if prototype_only is set to True, only print the function
# prototype
def print_func(prototype_only):

	out_file.write("//\n")

	if prototype_only:
		out_file.write("// function prototypes\n")
		out_file.write("//\n\n")
	else:
		out_file.write("// functions\n")
		out_file.write("//\n")

	sorted_funcs = sorted(visited_funcs)
	for func in sorted_funcs:

		results = ifc.decompileFunction(func, 0, monitor)

		if prototype_only:
			decomp = results.getDecompiledFunction().getSignature()
			out_file.write(decomp)
			out_file.write("\n")
		else:
			decomp = results.getDecompiledFunction().getC()
			out_file.write(decomp)

	out_file.write("\n")

def main():

	# prompt user for a list of functions to start with
	filename = askFile("Choose function list file:", "OK")

	println("Loading file:" + filename.path)
	for func_name in file(filename.absolutePath):

		func_name = func_name.strip()

		try:
			func = getFunction(func_name)
			if func == None:
				println("Failed to find " + func_name)
				continue

			current_funcs.append(func)
		except:
			println("Failed to find " + func_name)

	# must have at lesat one function
	if len(current_funcs) == 0:
		println("Error: need at least one starting function!!")
		return

	println("Found " + str(len(current_funcs)) + " starting function(s).")

	while True:
		# iterate through all functions, adding more as discovered
		if len(current_funcs) == 0:
			break

		curr_func = current_funcs.pop()
		visit_func(curr_func)

	while True:

		# iterate through all types, adding more as discovered
		if len(current_types) == 0:
			break

		curr_type = current_types.pop()
		visit_types(curr_type)

	# output to decomp.c
	print_enums()
	print_structs()
	print_func(True)
	print_func(False)
	out_file.close()

	println("Wrote " + str(len(visited_enums)) + " enum(s), " + str(len(visited_structs)) + " struct(s), and " + str(len(visited_funcs)) + " function(s) to decomp.c.")

main()

