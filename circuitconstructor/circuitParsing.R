require("compositions")

f <- data.frame(lines = scan(file="Circuit1.fhe", what="list", sep= "\n"), stringsAsFactors = FALSE)
f[,] <- gsub("\t", "", f[,])

# header line numbers
paramL <- which(f$lines == "Params")
inputL <- which(f$lines == "Input")
circL <- which(f$lines == "Circuits")
outputL <- which(f$lines == "Output")

# initializing variable data.frame storage
varComments <- data.frame(lines = which(grepl("#", f[,])))
varParams <- data.frame(name = character(), value = numeric(), stringsAsFactors = FALSE)
varInputs <- data.frame(name = character(), value = numeric(), stringsAsFactors = FALSE)
varCircuits <- data.frame(name = character(), operation = character(), value1 = character(), value2 = character(), stringsAsFactors = FALSE)


# functions
getRemoveComments = function(row){
  cmntIndex <- regexpr("#", f[row ,])[1]
  comment <- substr(f[row ,], cmntIndex, nchar(f[row ,]))
  f[row ,] <<- substr(f[row ,], 0, cmntIndex-1) #sneaky removal
  return (comment)
}

storeVar = function(start, end, splitChar, type){
  tempTable <- data.frame(name = character(), value = numeric(), stringsAsFactors = FALSE)
  for (i in (start+1):(end-1)){
    temp <- unlist(strsplit(f[i,], split= splitChar))
    temp <- data.frame(name = temp[1], value= temp[2], stringsAsFactors = FALSE)
    tempTable <- rbind(tempTable, temp)
  }
  
  if (type == "input"){
    # create binary value
    tempTable$value <- gsub(" ", "", tempTable$value)
    tempTable$value <- substr(tempTable$value, 2, nchar(tempTable$value)-1)
    tempTable$value <- unbinary(tempTable$value)
  }
  
  if (type == "circuit"){
    # separate value into operation and values
    for (i in 1:nrow(tempTable)){
      tempTable$operation[i] <- unlist(strsplit(tempTable$value[i], split=" "))[1]
      tempTable$value1[i] <- unlist(strsplit(tempTable$value[i], split=" "))[2]
      tempTable$value2[i] <- unlist(strsplit(tempTable$value[i], split=" "))[3]
    }
    tempTable$value <- NULL
  }
  return (tempTable)
}

# take out comments
varComments$comments <- sapply(varComments$lines, getRemoveComments)

# parameter storage
varParams <- storeVar(paramL, inputL, " = ", "param")
varInputs <- storeVar(inputL, circL, " = ", "input")
varOutput <- storeVar(outputL, nrow(f)+1, " := ", "output")
varCircuits <- storeVar(circL, outputL, " := ", "circuit")
