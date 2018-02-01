EchoUsage(){
    echo "USAGE:`basename $0` [-t] [-p 'comment'] [-d]"
	echo "	-t :hexo generate & test"
	echo "	-p :push to remote repository"
	echo "	-d :hexo generate & deploy"
}
if [[ $# -lt 1 ]];then  
	EchoUsage
	exit 1  
fi
while getopts 'tp:d' OPT; do
    case $OPT in
        t)
            OPT_TEST=true;;
        p)
            OPT_PUSH=true;
			PUSHCOMMENT="$OPTARG";;
        d)
            OPT_DEPLOY=true;;
        ?)
            EchoUsage
			exit 2
    esac
done
HEXOREBUILD=false
if [[ $OPT_PUSH = true ]]; then 
	if [[ ${#PUSHCOMMENT} < 2 ]]; then		
		NOWTIME=$(date "+ %G-%m-%d %H:%M:%S")
		PUSHCOMMENT="update ${NOWTIME}"
	fi
	PUSHCOMMENT="git commit -m \\\"${PUSHCOMMENT}\\\""
	git add -A
	echo `${PUSHCOMMENT}`
	echo ${PUSHCOMMENT}
	#git push gitpages blogSource
fi

if [[ $OPT_DEPLOY = true ]]; then 
	hexo clean && hexo g -d
	HEXOREBUILD=true
fi

if [[ $OPT_TEST = true ]]; then
	if [[ $HEXOREBUILD != true ]]; then
		HEXOREBUILD=true
		hexo clean && hexo g
	fi
	start http://localhost:4000/
	hexo s
fi