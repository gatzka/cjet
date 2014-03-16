require(ggplot2)
library(reshape2)

mt <- read.csv(file="roundtrip_mt.csv", head=TRUE, sep=" ")
epoll <- read.csv(file="roundtrip_epoll.csv", head=TRUE, sep=" ")

m <- merge(mt, epoll, by="MSGSIZE", suffixes=c(".mt", ".epoll"))
m["diff"] <- NA
m$diff <- m$time.epoll - m$time.mt
colnames(m) <- c("MSGSIZE", "multithread", "epoll", "diff")

df = melt(m, id.vars ="MSGSIZE", measure.vars = c("multithread","epoll"), variable.name="IO", value.name="time")

ggplot(data=df, aes(MSGSIZE, time, colour=IO)) + geom_point() + geom_smooth()

ggplot(data=m, aes(x=MSGSIZE, y=diff)) + geom_point() + geom_smooth()
