using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Antlr.Runtime;
using Antlr.Runtime.Tree;
using HtmlAgilityPack;
using JsParser.Net;

namespace Irv.Engine
{
    internal class HtmlResponseValidator
    {
        // Minimal length of LCS for taintful param and fragment of response to threat it as potentially dangerous
        private const int LcsLengthTreshold = 7;
        // Minimal count of tokens of parsed code to threat it as potentially dangerous
        private const int TokensCountTreshold = 4;
        // Minimal count of nodes at AST of parsed code to threat it as potentially dangerous
        private const int AstNodesCountTreshold = 1;
        // Hint: because of 'alert(0)' consist of 2 nodes, 5 tokens and 8 symbols :D

        // HTML event-hanlders attributes names
        private readonly string[] _htmlEventHanlders =
            {
                "fscommand", "onabort", "onactivate", "onafterprint",
                "onafterupdate", "onbeforeactivate", "onbeforecopy", "onbeforecut", "onbeforedeactivate",
                "onbeforeeditfocus", "onbeforepaste", "onbeforeprint", "onbeforeunload", "onbegin", "onblur", "onbounce",
                "oncanplay", "oncanplaythrough", "oncellchange", "onchange", "onclick", "oncontextmenu", "oncontrolselect",
                "oncopy", "oncut", "ondataavailable", "ondatasetchanged", "ondatasetcomplete", "ondblclick", "ondeactivate",
                "ondrag", "ondragdrop", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop",
                "ondurationchange", "onemptied", "onend", "onended", "onerror", "onerrorupdate", "onfilterchange",
                "onfinish", "onfocus", "onfocusin", "onfocusout", "onformchange", "onforminput", "onhaschange", "onhelp",
                "oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onlayoutcomplete", "onload", "onloadeddata",
                "onloadedmetadata", "onloadstart", "onlosecapture", "onmediacomplete", "onmediaerror", "onmessage",
                "onmousedown", "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover", "onmouseup",
                "onmousewheel", "onmove", "onmoveend", "onmovestart", "onoffline", "ononline", "onoutofsync", "onpagehide",
                "onpageshow", "onpaste", "onpause", "onplay", "onplaying", "onpopstate", "onprogress", "onpropertychange",
                "onratechange", "onreadystatechange", "onredo", "onrepeat", "onreset", "onresize", "onresizeend",
                "onresizestart", "onresume", "onreverse", "onrowdelete", "onrowexit", "onrowinserted", "onrowsenter",
                "onscroll", "onseek", "onseeked", "onseeking", "onselect", "onselectionchange", "onselectstart", "onstalled",
                "onstart", "onstop", "onstorage", "onsubmit", "onsuspend", "onsyncrestored", "ontimeerror", "ontimeupdate",
                "ontrackchange", "onundo", "onunload", "onurlflip", "onvolumechange", "onwaiting", "seeksegmenttime"
            };

        // HTML reference type attributes name
        private readonly string[] _htmlRefAttrs =
            {
                "src", "href", "background", "dynsrc", "lowsrc"
            };

        private readonly string[] _dangerousUriSchemes =
            {
                "data", "javascript", "vbscript", "livescript"
            };

        private readonly string[] _htmlNamedEntityReferences =
            {
                "&aacute", "&abreve", "&ac", "&acd", "&ace", "&acirc", "&acute", "&acy", "&aelig", "&af", "&afr",
                "&agrave", "&alefsym", "&aleph", "&alpha", "&amacr", "&amalg", "&amp", "&and", "&andand", "&andd",
                "&andslope", "&andv", "&ang", "&ange", "&angle", "&angmsd", "&angmsdaa", "&angmsdab", "&angmsdac",
                "&angmsdad", "&angmsdae", "&angmsdaf", "&angmsdag", "&angmsdah", "&angrt", "&angrtvb", "&angrtvbd",
                "&angsph", "&angst", "&angzarr", "&aogon", "&aopf", "&ap", "&apacir", "&ape", "&apid", "&apos",
                "&applyfunction", "&approx", "&approxeq", "&aring", "&ascr", "&assign", "&ast", "&asymp", "&asympeq",
                "&atilde", "&auml", "&awconint", "&awint", "&backcong", "&backepsilon", "&backprime", "&backsim",
                "&backsimeq", "&backslash", "&barv", "&barvee", "&barwed", "&barwedge", "&bbrk", "&bbrktbrk", "&bcong",
                "&bcy", "&bdquo", "&becaus", "&because", "&bemptyv", "&bepsi", "&bernou", "&bernoullis", "&beta",
                "&beth", "&between", "&bfr", "&bigcap", "&bigcirc", "&bigcup", "&bigodot", "&bigoplus", "&bigotimes",
                "&bigsqcup", "&bigstar", "&bigtriangledown", "&bigtriangleup", "&biguplus", "&bigvee", "&bigwedge",
                "&bkarow", "&blacklozenge", "&blacksquare", "&blacktriangle", "&blacktriangledown", "&blacktriangleleft"
                , "&blacktriangleright", "&blank", "&blk12", "&blk14", "&blk34", "&block", "&bne", "&bnequiv", "&bnot",
                "&bopf", "&bot", "&bottom", "&bowtie", "&boxbox", "&boxdl", "&boxdr", "&boxh", "&boxhd", "&boxhu",
                "&boxminus", "&boxplus", "&boxtimes", "&boxul", "&boxur", "&boxv", "&boxvh", "&boxvl", "&boxvr",
                "&bprime", "&breve", "&brvbar", "&bscr", "&bsemi", "&bsim", "&bsime", "&bsol", "&bsolb", "&bsolhsub",
                "&bull", "&bullet", "&bump", "&bumpe", "&bumpeq", "&cacute", "&cap", "&capand", "&capbrcup", "&capcap",
                "&capcup", "&capdot", "&capitaldifferentiald", "&caps", "&caret", "&caron", "&cayleys", "&ccaps",
                "&ccaron", "&ccedil", "&ccirc", "&cconint", "&ccups", "&ccupssm", "&cdot", "&cedil", "&cedilla",
                "&cemptyv", "&cent", "&centerdot", "&cfr", "&chcy", "&check", "&checkmark", "&chi", "&cir", "&circ",
                "&circeq", "&circlearrowleft", "&circlearrowright", "&circledast", "&circledcirc", "&circleddash",
                "&circledot", "&circledr", "&circleds", "&circleminus", "&circleplus", "&circletimes", "&cire",
                "&cirfnint", "&cirmid", "&cirscir", "&clockwisecontourintegral", "&closecurlydoublequote",
                "&closecurlyquote", "&clubs", "&clubsuit", "&colon", "&colone", "&coloneq", "&comma", "&commat", "&comp"
                , "&compfn", "&complement", "&complexes", "&cong", "&congdot", "&congruent", "&conint",
                "&contourintegral", "&copf", "&coprod", "&coproduct", "&copy", "&copysr",
                "&counterclockwisecontourintegral", "&crarr", "&cross", "&cscr", "&csub", "&csube", "&csup", "&csupe",
                "&ctdot", "&cudarrl", "&cudarrr", "&cuepr", "&cuesc", "&cularr", "&cularrp", "&cup", "&cupbrcap",
                "&cupcap", "&cupcup", "&cupdot", "&cupor", "&cups", "&curarr", "&curarrm", "&curlyeqprec",
                "&curlyeqsucc", "&curlyvee", "&curlywedge", "&curren", "&curvearrowleft", "&curvearrowright", "&cuvee",
                "&cuwed", "&cwconint", "&cwint", "&cylcty", "&dagger", "&daleth", "&darr", "&dash", "&dashv", "&dbkarow"
                , "&dblac", "&dcaron", "&dcy", "&dd", "&ddagger", "&ddarr", "&ddotrahd", "&ddotseq", "&deg", "&del",
                "&delta", "&demptyv", "&dfisht", "&dfr", "&dhar", "&dharl", "&dharr", "&diacriticalacute",
                "&diacriticaldot", "&diacriticaldoubleacute", "&diacriticalgrave", "&diacriticaltilde", "&diam",
                "&diamond", "&diamondsuit", "&diams", "&die", "&differentiald", "&digamma", "&disin", "&div", "&divide",
                "&divideontimes", "&divonx", "&djcy", "&dlcorn", "&dlcrop", "&dollar", "&dopf", "&dot", "&dotdot",
                "&doteq", "&doteqdot", "&dotequal", "&dotminus", "&dotplus", "&dotsquare", "&doublebarwedge",
                "&doublecontourintegral", "&doubledot", "&doubledownarrow", "&doubleleftarrow", "&doubleleftrightarrow",
                "&doublelefttee", "&doublelongleftarrow", "&doublelongleftrightarrow", "&doublelongrightarrow",
                "&doublerightarrow", "&doublerighttee", "&doubleuparrow", "&doubleupdownarrow", "&doubleverticalbar",
                "&downarrow", "&downarrowbar", "&downarrowuparrow", "&downbreve", "&downdownarrows", "&downharpoonleft",
                "&downharpoonright", "&downleftrightvector", "&downleftteevector", "&downleftvector",
                "&downleftvectorbar", "&downrightteevector", "&downrightvector", "&downrightvectorbar", "&downtee",
                "&downteearrow", "&drbkarow", "&drcorn", "&drcrop", "&dscr", "&dscy", "&dsol", "&dstrok", "&dtdot",
                "&dtri", "&dtrif", "&duarr", "&duhar", "&dwangle", "&dzcy", "&dzigrarr", "&eacute", "&easter", "&ecaron"
                , "&ecir", "&ecirc", "&ecolon", "&ecy", "&eddot", "&edot", "&ee", "&efdot", "&efr", "&eg", "&egrave",
                "&egs", "&egsdot", "&el", "&element", "&elinters", "&ell", "&els", "&elsdot", "&emacr", "&empty",
                "&emptyset", "&emptysmallsquare", "&emptyv", "&emptyverysmallsquare", "&emsp", "&emsp13", "&emsp14",
                "&eng", "&ensp", "&eogon", "&eopf", "&epar", "&eparsl", "&eplus", "&epsi", "&epsilon", "&epsiv",
                "&eqcirc", "&eqcolon", "&eqsim", "&eqslantgtr", "&eqslantless", "&equal", "&equals", "&equaltilde",
                "&equest", "&equilibrium", "&equiv", "&equivdd", "&eqvparsl", "&erarr", "&erdot", "&escr", "&esdot",
                "&esim", "&eta", "&eth", "&euml", "&euro", "&excl", "&exist", "&exists", "&expectation", "&exponentiale"
                , "&fallingdotseq", "&fcy", "&female", "&ffilig", "&fflig", "&ffllig", "&ffr", "&filig",
                "&filledsmallsquare", "&filledverysmallsquare", "&fjlig", "&flat", "&fllig", "&fltns", "&fnof", "&fopf",
                "&forall", "&fork", "&forkv", "&fouriertrf", "&fpartint", "&frac12", "&frac13", "&frac14", "&frac15",
                "&frac16", "&frac18", "&frac23", "&frac25", "&frac34", "&frac35", "&frac38", "&frac45", "&frac56",
                "&frac58", "&frac78", "&frasl", "&frown", "&fscr", "&gacute", "&gamma", "&gammad", "&gap", "&gbreve",
                "&gcedil", "&gcirc", "&gcy", "&gdot", "&ge", "&gel", "&geq", "&geqq", "&geqslant", "&ges", "&gescc",
                "&gesdot", "&gesdoto", "&gesdotol", "&gesl", "&gesles", "&gfr", "&gg", "&ggg", "&gimel", "&gjcy", "&gl",
                "&gla", "&gle", "&glj", "&gnap", "&gnapprox", "&gne", "&gneq", "&gneqq", "&gnsim", "&gopf", "&grave",
                "&greaterequal", "&greaterequalless", "&greaterfullequal", "&greatergreater", "&greaterless",
                "&greaterslantequal", "&greatertilde", "&gscr", "&gsim", "&gsime", "&gsiml", "&gt", "&gtcc", "&gtcir",
                "&gtdot", "&gtlpar", "&gtquest", "&gtrapprox", "&gtrarr", "&gtrdot", "&gtreqless", "&gtreqqless",
                "&gtrless", "&gtrsim", "&gvertneqq", "&gvne", "&hacek", "&hairsp", "&half", "&hamilt", "&hardcy",
                "&harr", "&harrcir", "&harrw", "&hat", "&hbar", "&hcirc", "&hearts", "&heartsuit", "&hellip", "&hercon",
                "&hfr", "&hilbertspace", "&hksearow", "&hkswarow", "&hoarr", "&homtht", "&hookleftarrow",
                "&hookrightarrow", "&hopf", "&horbar", "&horizontalline", "&hscr", "&hslash", "&hstrok", "&humpdownhump"
                , "&humpequal", "&hybull", "&hyphen", "&iacute", "&ic", "&icirc", "&icy", "&idot", "&iecy", "&iexcl",
                "&iff", "&ifr", "&igrave", "&ii", "&iiiint", "&iiint", "&iinfin", "&iiota", "&ijlig", "&im", "&imacr",
                "&image", "&imaginaryi", "&imagline", "&imagpart", "&imath", "&imof", "&imped", "&implies", "&in",
                "&incare", "&infin", "&infintie", "&inodot", "&int", "&intcal", "&integers", "&integral", "&intercal",
                "&intersection", "&intlarhk", "&intprod", "&invisiblecomma", "&invisibletimes", "&iocy", "&iogon",
                "&iopf", "&iota", "&iprod", "&iquest", "&iscr", "&isin", "&isindot", "&isine", "&isins", "&isinsv",
                "&isinv", "&it", "&itilde", "&iukcy", "&iuml", "&jcirc", "&jcy", "&jfr", "&jmath", "&jopf", "&jscr",
                "&jsercy", "&jukcy", "&kappa", "&kappav", "&kcedil", "&kcy", "&kfr", "&kgreen", "&khcy", "&kjcy",
                "&kopf", "&kscr", "&laarr", "&lacute", "&laemptyv", "&lagran", "&lambda", "&lang", "&langd", "&langle",
                "&lap", "&laplacetrf", "&laquo", "&larr", "&larrb", "&larrbfs", "&larrfs", "&larrhk", "&larrlp",
                "&larrpl", "&larrsim", "&larrtl", "&lat", "&latail", "&late", "&lates", "&lbarr", "&lbbrk", "&lbrace",
                "&lbrack", "&lbrke", "&lbrksld", "&lbrkslu", "&lcaron", "&lcedil", "&lceil", "&lcub", "&lcy", "&ldca",
                "&ldquo", "&ldquor", "&ldrdhar", "&ldrushar", "&ldsh", "&le", "&leftanglebracket", "&leftarrow",
                "&leftarrowbar", "&leftarrowrightarrow", "&leftarrowtail", "&leftceiling", "&leftdoublebracket",
                "&leftdownteevector", "&leftdownvector", "&leftdownvectorbar", "&leftfloor", "&leftharpoondown",
                "&leftharpoonup", "&leftleftarrows", "&leftrightarrow", "&leftrightarrows", "&leftrightharpoons",
                "&leftrightsquigarrow", "&leftrightvector", "&lefttee", "&leftteearrow", "&leftteevector",
                "&leftthreetimes", "&lefttriangle", "&lefttrianglebar", "&lefttriangleequal", "&leftupdownvector",
                "&leftupteevector", "&leftupvector", "&leftupvectorbar", "&leftvector", "&leftvectorbar", "&leg", "&leq"
                , "&leqq", "&leqslant", "&les", "&lescc", "&lesdot", "&lesdoto", "&lesdotor", "&lesg", "&lesges",
                "&lessapprox", "&lessdot", "&lesseqgtr", "&lesseqqgtr", "&lessequalgreater", "&lessfullequal",
                "&lessgreater", "&lessgtr", "&lessless", "&lesssim", "&lessslantequal", "&lesstilde", "&lfisht",
                "&lfloor", "&lfr", "&lg", "&lge", "&lhar", "&lhard", "&lharu", "&lharul", "&lhblk", "&ljcy", "&ll",
                "&llarr", "&llcorner", "&lleftarrow", "&llhard", "&lltri", "&lmidot", "&lmoust", "&lmoustache", "&lnap",
                "&lnapprox", "&lne", "&lneq", "&lneqq", "&lnsim", "&loang", "&loarr", "&lobrk", "&longleftarrow",
                "&longleftrightarrow", "&longmapsto", "&longrightarrow", "&looparrowleft", "&looparrowright", "&lopar",
                "&lopf", "&loplus", "&lotimes", "&lowast", "&lowbar", "&lowerleftarrow", "&lowerrightarrow", "&loz",
                "&lozenge", "&lozf", "&lpar", "&lparlt", "&lrarr", "&lrcorner", "&lrhar", "&lrhard", "&lrm", "&lrtri",
                "&lsaquo", "&lscr", "&lsh", "&lsim", "&lsime", "&lsimg", "&lsqb", "&lsquo", "&lsquor", "&lstrok", "&lt",
                "&ltcc", "&ltcir", "&ltdot", "&lthree", "&ltimes", "&ltlarr", "&ltquest", "&ltri", "&ltrie", "&ltrif",
                "&ltrpar", "&lurdshar", "&luruhar", "&lvertneqq", "&lvne", "&macr", "&male", "&malt", "&maltese", "&map"
                , "&mapsto", "&mapstodown", "&mapstoleft", "&mapstoup", "&marker", "&mcomma", "&mcy", "&mdash", "&mddot"
                , "&measuredangle", "&mediumspace", "&mellintrf", "&mfr", "&mho", "&micro", "&mid", "&midast", "&midcir"
                , "&middot", "&minus", "&minusb", "&minusd", "&minusdu", "&minusplus", "&mlcp", "&mldr", "&mnplus",
                "&models", "&mopf", "&mp", "&mscr", "&mstpos", "&mu", "&multimap", "&mumap", "&nabla", "&nacute",
                "&nang", "&nap", "&nape", "&napid", "&napos", "&napprox", "&natur", "&natural", "&naturals", "&nbsp",
                "&nbump", "&nbumpe", "&ncap", "&ncaron", "&ncedil", "&ncong", "&ncongdot", "&ncup", "&ncy", "&ndash",
                "&ne", "&nearhk", "&nearr", "&nearrow", "&nedot", "&negativemediumspace", "&negativethickspace",
                "&negativethinspace", "&negativeverythinspace", "&nequiv", "&nesear", "&nesim", "&nestedgreatergreater",
                "&nestedlessless", "&newline", "&nexist", "&nexists", "&nfr", "&nge", "&ngeq", "&ngeqq", "&ngeqslant",
                "&nges", "&ngg", "&ngsim", "&ngt", "&ngtr", "&ngtv", "&nharr", "&nhpar", "&ni", "&nis", "&nisd", "&niv",
                "&njcy", "&nlarr", "&nldr", "&nle", "&nleftarrow", "&nleftrightarrow", "&nleq", "&nleqq", "&nleqslant",
                "&nles", "&nless", "&nll", "&nlsim", "&nlt", "&nltri", "&nltrie", "&nltv", "&nmid", "&nobreak",
                "&nonbreakingspace", "&nopf", "&not", "&notcongruent", "&notcupcap", "&notdoubleverticalbar",
                "&notelement", "&notequal", "&notequaltilde", "&notexists", "&notgreater", "&notgreaterequal",
                "&notgreaterfullequal", "&notgreatergreater", "&notgreaterless", "&notgreaterslantequal",
                "&notgreatertilde", "&nothumpdownhump", "&nothumpequal", "&notin", "&notindot", "&notine", "&notinva",
                "&notinvb", "&notinvc", "&notlefttriangle", "&notlefttrianglebar", "&notlefttriangleequal", "&notless",
                "&notlessequal", "&notlessgreater", "&notlessless", "&notlessslantequal", "&notlesstilde",
                "&notnestedgreatergreater", "&notnestedlessless", "&notni", "&notniva", "&notnivb", "&notnivc",
                "&notprecedes", "&notprecedesequal", "&notprecedesslantequal", "&notreverseelement", "&notrighttriangle"
                , "&notrighttrianglebar", "&notrighttriangleequal", "&notsquaresubset", "&notsquaresubsetequal",
                "&notsquaresuperset", "&notsquaresupersetequal", "&notsubset", "&notsubsetequal", "&notsucceeds",
                "&notsucceedsequal", "&notsucceedsslantequal", "&notsucceedstilde", "&notsuperset", "&notsupersetequal",
                "&nottilde", "&nottildeequal", "&nottildefullequal", "&nottildetilde", "&notverticalbar", "&npar",
                "&nparallel", "&nparsl", "&npart", "&npolint", "&npr", "&nprcue", "&npre", "&nprec", "&npreceq",
                "&nrarr", "&nrarrc", "&nrarrw", "&nrightarrow", "&nrtri", "&nrtrie", "&nsc", "&nsccue", "&nsce", "&nscr"
                , "&nshortmid", "&nshortparallel", "&nsim", "&nsime", "&nsimeq", "&nsmid", "&nspar", "&nsqsube",
                "&nsqsupe", "&nsub", "&nsube", "&nsubset", "&nsubseteq", "&nsubseteqq", "&nsucc", "&nsucceq", "&nsup",
                "&nsupe", "&nsupset", "&nsupseteq", "&nsupseteqq", "&ntgl", "&ntilde", "&ntlg", "&ntriangleleft",
                "&ntrianglelefteq", "&ntriangleright", "&ntrianglerighteq", "&nu", "&num", "&numero", "&numsp", "&nvap",
                "&nvdash", "&nvge", "&nvgt", "&nvharr", "&nvinfin", "&nvlarr", "&nvle", "&nvlt", "&nvltrie", "&nvrarr",
                "&nvrtrie", "&nvsim", "&nwarhk", "&nwarr", "&nwarrow", "&nwnear", "&oacute", "&oast", "&ocir", "&ocirc",
                "&ocy", "&odash", "&odblac", "&odiv", "&odot", "&odsold", "&oelig", "&ofcir", "&ofr", "&ogon", "&ograve"
                , "&ogt", "&ohbar", "&ohm", "&oint", "&olarr", "&olcir", "&olcross", "&oline", "&olt", "&omacr",
                "&omega", "&omicron", "&omid", "&ominus", "&oopf", "&opar", "&opencurlydoublequote", "&opencurlyquote",
                "&operp", "&oplus", "&or", "&orarr", "&ord", "&order", "&orderof", "&ordf", "&ordm", "&origof", "&oror",
                "&orslope", "&orv", "&os", "&oscr", "&oslash", "&osol", "&otilde", "&otimes", "&otimesas", "&ouml",
                "&ovbar", "&overbar", "&overbrace", "&overbracket", "&overparenthesis", "&par", "&para", "&parallel",
                "&parsim", "&parsl", "&part", "&partiald", "&pcy", "&percnt", "&period", "&permil", "&perp", "&pertenk",
                "&pfr", "&phi", "&phiv", "&phmmat", "&phone", "&pi", "&pitchfork", "&piv", "&planck", "&planckh",
                "&plankv", "&plus", "&plusacir", "&plusb", "&pluscir", "&plusdo", "&plusdu", "&pluse", "&plusminus",
                "&plusmn", "&plussim", "&plustwo", "&pm", "&poincareplane", "&pointint", "&popf", "&pound", "&pr",
                "&prap", "&prcue", "&pre", "&prec", "&precapprox", "&preccurlyeq", "&precedes", "&precedesequal",
                "&precedesslantequal", "&precedestilde", "&preceq", "&precnapprox", "&precneqq", "&precnsim", "&precsim"
                , "&prime", "&primes", "&prnap", "&prne", "&prnsim", "&prod", "&product", "&profalar", "&profline",
                "&profsurf", "&prop", "&proportion", "&proportional", "&propto", "&prsim", "&prurel", "&pscr", "&psi",
                "&puncsp", "&qfr", "&qint", "&qopf", "&qprime", "&qscr", "&quaternions", "&quatint", "&quest",
                "&questeq", "&quot", "&raarr", "&race", "&racute", "&radic", "&raemptyv", "&rang", "&rangd", "&range",
                "&rangle", "&raquo", "&rarr", "&rarrap", "&rarrb", "&rarrbfs", "&rarrc", "&rarrfs", "&rarrhk", "&rarrlp"
                , "&rarrpl", "&rarrsim", "&rarrtl", "&rarrw", "&ratail", "&ratio", "&rationals", "&rbarr", "&rbbrk",
                "&rbrace", "&rbrack", "&rbrke", "&rbrksld", "&rbrkslu", "&rcaron", "&rcedil", "&rceil", "&rcub", "&rcy",
                "&rdca", "&rdldhar", "&rdquo", "&rdquor", "&rdsh", "&re", "&real", "&realine", "&realpart", "&reals",
                "&rect", "&reg", "&reverseelement", "&reverseequilibrium", "&reverseupequilibrium", "&rfisht", "&rfloor"
                , "&rfr", "&rhar", "&rhard", "&rharu", "&rharul", "&rho", "&rhov", "&rightanglebracket", "&rightarrow",
                "&rightarrowbar", "&rightarrowleftarrow", "&rightarrowtail", "&rightceiling", "&rightdoublebracket",
                "&rightdownteevector", "&rightdownvector", "&rightdownvectorbar", "&rightfloor", "&rightharpoondown",
                "&rightharpoonup", "&rightleftarrows", "&rightleftharpoons", "&rightrightarrows", "&rightsquigarrow",
                "&righttee", "&rightteearrow", "&rightteevector", "&rightthreetimes", "&righttriangle",
                "&righttrianglebar", "&righttriangleequal", "&rightupdownvector", "&rightupteevector", "&rightupvector",
                "&rightupvectorbar", "&rightvector", "&rightvectorbar", "&ring", "&risingdotseq", "&rlarr", "&rlhar",
                "&rlm", "&rmoust", "&rmoustache", "&rnmid", "&roang", "&roarr", "&robrk", "&ropar", "&ropf", "&roplus",
                "&rotimes", "&roundimplies", "&rpar", "&rpargt", "&rppolint", "&rrarr", "&rrightarrow", "&rsaquo",
                "&rscr", "&rsh", "&rsqb", "&rsquo", "&rsquor", "&rthree", "&rtimes", "&rtri", "&rtrie", "&rtrif",
                "&rtriltri", "&ruledelayed", "&ruluhar", "&rx", "&sacute", "&sbquo", "&sc", "&scap", "&scaron", "&sccue"
                , "&sce", "&scedil", "&scirc", "&scnap", "&scne", "&scnsim", "&scpolint", "&scsim", "&scy", "&sdot",
                "&sdotb", "&sdote", "&searhk", "&searr", "&searrow", "&sect", "&semi", "&seswar", "&setminus", "&setmn",
                "&sext", "&sfr", "&sfrown", "&sharp", "&shchcy", "&shcy", "&shortdownarrow", "&shortleftarrow",
                "&shortmid", "&shortparallel", "&shortrightarrow", "&shortuparrow", "&shy", "&sigma", "&sigmaf",
                "&sigmav", "&sim", "&simdot", "&sime", "&simeq", "&simg", "&simge", "&siml", "&simle", "&simne",
                "&simplus", "&simrarr", "&slarr", "&smallcircle", "&smallsetminus", "&smashp", "&smeparsl", "&smid",
                "&smile", "&smt", "&smte", "&smtes", "&softcy", "&sol", "&solb", "&solbar", "&sopf", "&spades",
                "&spadesuit", "&spar", "&sqcap", "&sqcaps", "&sqcup", "&sqcups", "&sqrt", "&sqsub", "&sqsube",
                "&sqsubset", "&sqsubseteq", "&sqsup", "&sqsupe", "&sqsupset", "&sqsupseteq", "&squ", "&square",
                "&squareintersection", "&squaresubset", "&squaresubsetequal", "&squaresuperset", "&squaresupersetequal",
                "&squareunion", "&squarf", "&squf", "&srarr", "&sscr", "&ssetmn", "&ssmile", "&sstarf", "&star",
                "&starf", "&straightepsilon", "&straightphi", "&strns", "&sub", "&subdot", "&sube", "&subedot",
                "&submult", "&subne", "&subplus", "&subrarr", "&subset", "&subseteq", "&subseteqq", "&subsetequal",
                "&subsetneq", "&subsetneqq", "&subsim", "&subsub", "&subsup", "&succ", "&succapprox", "&succcurlyeq",
                "&succeeds", "&succeedsequal", "&succeedsslantequal", "&succeedstilde", "&succeq", "&succnapprox",
                "&succneqq", "&succnsim", "&succsim", "&suchthat", "&sum", "&sung", "&sup", "&sup1", "&sup2", "&sup3",
                "&supdot", "&supdsub", "&supe", "&supedot", "&superset", "&supersetequal", "&suphsol", "&suphsub",
                "&suplarr", "&supmult", "&supne", "&supplus", "&supset", "&supseteq", "&supseteqq", "&supsetneq",
                "&supsetneqq", "&supsim", "&supsub", "&supsup", "&swarhk", "&swarr", "&swarrow", "&swnwar", "&szlig",
                "&tab", "&target", "&tau", "&tbrk", "&tcaron", "&tcedil", "&tcy", "&tdot", "&telrec", "&tfr", "&there4",
                "&therefore", "&theta", "&thetasym", "&thetav", "&thickapprox", "&thicksim", "&thickspace", "&thinsp",
                "&thinspace", "&thkap", "&thksim", "&thorn", "&tilde", "&tildeequal", "&tildefullequal", "&tildetilde",
                "&times", "&timesb", "&timesbar", "&timesd", "&tint", "&toea", "&top", "&topbot", "&topcir", "&topf",
                "&topfork", "&tosa", "&tprime", "&trade", "&triangle", "&triangledown", "&triangleleft",
                "&trianglelefteq", "&triangleq", "&triangleright", "&trianglerighteq", "&tridot", "&trie", "&triminus",
                "&tripledot", "&triplus", "&trisb", "&tritime", "&trpezium", "&tscr", "&tscy", "&tshcy", "&tstrok",
                "&twixt", "&twoheadleftarrow", "&twoheadrightarrow", "&uacute", "&uarr", "&uarrocir", "&ubrcy",
                "&ubreve", "&ucirc", "&ucy", "&udarr", "&udblac", "&udhar", "&ufisht", "&ufr", "&ugrave", "&uhar",
                "&uharl", "&uharr", "&uhblk", "&ulcorn", "&ulcorner", "&ulcrop", "&ultri", "&umacr", "&uml", "&underbar"
                , "&underbrace", "&underbracket", "&underparenthesis", "&union", "&unionplus", "&uogon", "&uopf",
                "&uparrow", "&uparrowbar", "&uparrowdownarrow", "&updownarrow", "&upequilibrium", "&upharpoonleft",
                "&upharpoonright", "&uplus", "&upperleftarrow", "&upperrightarrow", "&upsi", "&upsih", "&upsilon",
                "&uptee", "&upteearrow", "&upuparrows", "&urcorn", "&urcorner", "&urcrop", "&uring", "&urtri", "&uscr",
                "&utdot", "&utilde", "&utri", "&utrif", "&uuarr", "&uuml", "&uwangle", "&vangrt", "&varepsilon",
                "&varkappa", "&varnothing", "&varphi", "&varpi", "&varpropto", "&varr", "&varrho", "&varsigma",
                "&varsubsetneq", "&varsubsetneqq", "&varsupsetneq", "&varsupsetneqq", "&vartheta", "&vartriangleleft",
                "&vartriangleright", "&vbar", "&vbarv", "&vcy", "&vdash", "&vdashl", "&vee", "&veebar", "&veeeq",
                "&vellip", "&verbar", "&vert", "&verticalbar", "&verticalline", "&verticalseparator", "&verticaltilde",
                "&verythinspace", "&vfr", "&vltri", "&vnsub", "&vnsup", "&vopf", "&vprop", "&vrtri", "&vscr", "&vsubne",
                "&vsupne", "&vvdash", "&vzigzag", "&wcirc", "&wedbar", "&wedge", "&wedgeq", "&weierp", "&wfr", "&wopf",
                "&wp", "&wr", "&wreath", "&wscr", "&xcap", "&xcirc", "&xcup", "&xdtri", "&xfr", "&xharr", "&xi",
                "&xlarr", "&xmap", "&xnis", "&xodot", "&xopf", "&xoplus", "&xotime", "&xrarr", "&xscr", "&xsqcup",
                "&xuplus", "&xutri", "&xvee", "&xwedge", "&yacute", "&yacy", "&ycirc", "&ycy", "&yen", "&yfr", "&yicy",
                "&yopf", "&yscr", "&yucy", "&yuml", "&zacute", "&zcaron", "&zcy", "&zdot", "&zeetrf", "&zerowidthspace",
                "&zeta", "&zfr", "&zhcy", "&zigrarr", "&zopf", "&zscr", "&zwj", "&zwnj"
            };

        public bool IsValidHtmlResponseString(List<RequestValidationParam> taintfulParams, string responseText, out RequestValidationParam dangerousParam)
        {
            dangerousParam = null;

            // HACK: Deny null-byte injection techniques. Perhaps, there are a better place and method to implement it.
            if (responseText.IndexOf('\0') != -1)
            {
                dangerousParam = new RequestValidationParam("null-byte", "Undefined", "...\\0");
                return false;
            }

            var htmlDocument = new HtmlDocument();
            htmlDocument.LoadHtml(responseText);

            if (htmlDocument.DocumentNode == null) return true;

            // Get boundaries for all occurences of request params in response text
            var insertionsMap =
                InsertionsMap.FindAllPrecise(
                    taintfulParams,
                    responseText);

            if (insertionsMap.Count == 0) return true;

            // In case of parse errors, needed a check that positions of errors isn't included to insertions map
            if (htmlDocument.ParseErrors != null && htmlDocument.ParseErrors.Count() != 0)
            {
                foreach (var htmlParseError in htmlDocument.ParseErrors)
                {
                    foreach (var insertionArea in insertionsMap)
                    {
                        if (!insertionArea.Includes(htmlParseError.StreamPosition)) continue;

                        // Inclusion found (integrity of response has been violated by request parameter at error position)
                        dangerousParam = insertionArea.Param;
                        return false;
                    }
                }
            }

            // Walk through elements of parsed response to check its integrity
            foreach (
                var node in
                    htmlDocument.DocumentNode.Descendants()
                                .Where(x => x.NodeType == HtmlNodeType.Element))
            {
                var nodeBeginPosition = node.StreamPosition;
                var nodeEndPosition = nodeBeginPosition + node.OuterHtml.Length;

                foreach (
                    var insertionArea in
                        insertionsMap.Where(ia => ia.Includes(nodeBeginPosition, nodeEndPosition)))
                {
                    // HACK: Deny IE related bypass technique (http://www.securityfocus.com/archive/1/524043)
                    if (node.OuterHtml.Contains("<%") && (insertionArea.Param.Value.Contains("<%")))
                    {
                        dangerousParam = insertionArea.Param;
                        return false;
                    }
                    // Check if start position of node was included to insertions map
                    if (insertionArea.Includes(nodeBeginPosition))
                    {
                        // Inclusion found (node was injected by request parameter)
                        dangerousParam = insertionArea.Param;
                        return false;
                    }

                    foreach (var attr in node.Attributes)
                    {
                        var attrNameBeginPosition = attr.StreamPosition;

                        if (insertionArea.Includes(attrNameBeginPosition))
                        {
                            // Inclusion found (attribute was injected by request parameter)
                            dangerousParam = insertionArea.Param;
                            return false;
                        }

                        var attrValueBeginPosition = responseText.IndexOf(attr.Value, attrNameBeginPosition,
                                                                            StringComparison.Ordinal);
                        var attrValueEndPosition = attrValueBeginPosition + attr.Value.Length;

                        // Skip if attribute value wasn't tainted by request parameter
                        if (!insertionArea.Includes(attrValueBeginPosition, attrValueEndPosition)) continue;

                        // Skip if attribute value passes validation
                        if (ValidateAttrWithParam(attr.Name, attr.Value, insertionArea.Param.Value)) continue;

                        // Attribute value is dangerously tainted
                        dangerousParam = insertionArea.Param;
                        return false;
                    }
                }

                if (node.Name != "script" || string.IsNullOrEmpty(node.InnerText)) continue;

                // Validate javscript code inside <script /> tag
                var scriptBeginPosition = responseText.IndexOf(node.InnerText, nodeBeginPosition, StringComparison.Ordinal);
                var scriptEndPosition = scriptBeginPosition + node.InnerText.Length;

                foreach (
                    var insertionArea in
                        insertionsMap.Where(ia => ia.Includes(scriptBeginPosition, scriptEndPosition)))
                {
                    if (ValidateJsWithParam(node.InnerText, insertionArea.Param.Value)) continue;

                    // Javascript code is dangerously tainted
                    dangerousParam = insertionArea.Param;
                    return false;
                }

                if (node.Name != "style" || string.IsNullOrEmpty(node.InnerText)) continue;

                // TODO: Add integrity validation of style nodes
            }
            return true;
        }

        private bool ValidateAttrWithParam(string attrName, string attrValue, string paramValue)
        {
            if (_htmlEventHanlders.Contains(attrName))
            {
                return ValidateJsWithParam(attrValue, paramValue);
            }

            if (_htmlRefAttrs.Contains(attrName))
            {
                // Tainted URI shouldn't contain any non-urlencoded HTML entities 
                if (attrValue.Contains("&#") || _htmlNamedEntityReferences.Any(attrValue.Contains)) return false;

                if (attrValue.Contains(":"))
                {
                    Uri uri;
                    var result = Uri.TryCreate(attrValue, UriKind.RelativeOrAbsolute, out uri);

                    // Malformed URI
                    if (!result) return false;

                    // Because of attrValue contains ":" character, it should be absolute
                    if (!uri.IsAbsoluteUri) return false;

                    try
                    {
                        // Deny dangerous schemes
                        if (_dangerousUriSchemes.Contains(uri.Scheme)) result = false;
                    }
                    // InvalidOperationException throws if scheme part malformed with whitespace characters
                    catch (InvalidOperationException)
                    {
                        result = false;
                    }
                    return result;
                }
            }

            if (attrName == "style")
            {
                // TODO: Add integrity validation of style attrs
                return true;
            }

            return true;
        }

        private bool ValidateJsWithParam(string jsValue, string paramValue)
        {
            CommonTree tree;
            string lcs;
            // Javascript code integrity was violated by request param
            if (!IsValidJsCode(jsValue, out tree)) return false;

            // Skip if common part of attribute value and taintful parameter less than defined treshold
            return LongestCommonSubstring(jsValue, paramValue, out lcs) <= LcsLengthTreshold
                // Value of parameter should be treated as harmless only if it whole fits at one token
                || IsTreeToken(tree, lcs);
        }

        private bool IsTreeToken(CommonTree tree, string value)
        {
            if (tree.Children == null) return false;

            var isTreeToken = false;

            foreach (CommonTree child in tree.Children)
            {
                if (isTreeToken || child.Token.Text.IndexOf(value, StringComparison.Ordinal) != -1)
                {
                    return true;
                }
                isTreeToken |= IsTreeToken(child, value);
            }

            return isTreeToken;
        }

        private bool IsValidJsCode(string value, out CommonTree tree)
        {
            var lexer = new JavaScriptLexer(new ANTLRStringStream(string.Format("{0}", value)));
            var parser = new JavaScriptParser(new CommonTokenStream(lexer));
            tree = null;
            try
            {
                var program = parser.program();
                if ((parser.NumberOfSyntaxErrors == 0) &&
                    (((CommonTree)program.Tree).ChildCount > AstNodesCountTreshold) &&
                    parser.TokenStream.Count > TokensCountTreshold)
                {
                    tree = (CommonTree)program.Tree;
                    return true;
                }
            }
            // ReSharper disable EmptyGeneralCatchClause
            catch
            { }
            // ReSharper restore EmptyGeneralCatchClause
            return false;
        }

        private int LongestCommonSubstring(string str1, string str2, out string sequence)
        {
            sequence = string.Empty;
            if (String.IsNullOrEmpty(str1) || String.IsNullOrEmpty(str2))
                return 0;

            var num = new int[str1.Length, str2.Length];
            var maxlen = 0;
            var lastSubsBegin = 0;
            var sequenceBuilder = new StringBuilder();

            for (var i = 0; i < str1.Length; i++)
            {
                for (var j = 0; j < str2.Length; j++)
                {
                    if (str1[i] != str2[j])
                        num[i, j] = 0;
                    else
                    {
                        if ((i == 0) || (j == 0))
                            num[i, j] = 1;
                        else
                            num[i, j] = 1 + num[i - 1, j - 1];

                        if (num[i, j] > maxlen)
                        {
                            maxlen = num[i, j];
                            var thisSubsBegin = i - num[i, j] + 1;
                            if (lastSubsBegin == thisSubsBegin)
                            {//if the current LCS is the same as the last time this block ran
                                sequenceBuilder.Append(str1[i]);
                            }
                            else //this block resets the string builder if a different LCS is found
                            {
                                lastSubsBegin = thisSubsBegin;
                                sequenceBuilder.Length = 0; //clear it
                                sequenceBuilder.Append(str1.Substring(lastSubsBegin, (i + 1) - lastSubsBegin));
                            }
                        }
                    }
                }
            }
            sequence = sequenceBuilder.ToString();
            return maxlen;
        }
    }
}
