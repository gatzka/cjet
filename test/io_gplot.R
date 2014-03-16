require(ggplot2)
library(reshape2)

mt <- read.csv(file="roundtrip_mt.csv", head=TRUE, sep=" ")
epoll <- read.csv(file="roundtrip_epoll.csv", head=TRUE, sep=" ")

m <- merge(mt, epoll, by="MSGSIZE", suffixes=c(".mt", ".epoll"))
m["diff"] <- NA
m$diff <- m$time.epoll - m$time.mt
colnames(m) <- c("MSGSIZE", "multithread", "epoll", "diff")

df = melt(m, id.vars ="MSGSIZE", measure.vars = c("multithread","epoll"), variable.name="IO", value.name="time")

g <- ggplot()
g <- g + geom_point(data=df, aes(x=MSGSIZE, y=time, colour=IO), alpha=0.3)
g <- g + geom_smooth(data=df, method=loess, aes(x=MSGSIZE, y=time, colour=IO))
g

ggplot(data=m, aes(x=MSGSIZE, y=diff)) + geom_point() + geom_smooth()
