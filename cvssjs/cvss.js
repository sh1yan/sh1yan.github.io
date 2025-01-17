/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }
                
    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');
    
    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }
    
*/

var CVSS = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: '攻击向量&sdot;AV',
        AC: '攻击复杂度&sdot;AC',
        PR: '所需权限&sdot;PR',
        UI: '用户交互&sdot;UI',
        S: '范围&sdot;S',
        C: '保密性&sdot;C',
        I: '完整性&sdot;I',
        A: '可用性&sdot;A'
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: '网络 (N)',
                d: "<b>最差：</b>易受攻击的组件绑定到网络堆栈，可能的攻击者的范围不仅包括以下列出的其他选项，甚至包括整个互联网。这种漏洞通常被称为“可远程利用”，可以认为是在协议级别上，攻击在经过一个或多个网络跳数（例如，经过一个或多个路由器）后仍可被利用。"
            },
            A: {
                l: '相邻的 (A)',
                d: "<b>更糟：</b>易受攻击的组件绑定到网络堆栈，但攻击在协议级别上仅限于逻辑上相邻的拓扑结构。这可能意味着攻击必须从相同的共享物理（例如，蓝牙或IEEE 802.11）或逻辑（例如，本地IP子网）网络发起，或者从一个安全的或其他受限的管理域（例如，MPLS，到管理网络区域的安全VPN）内部发起。一种相邻攻击的例子是ARP（IPv4）或邻居发现（IPv6）洪泛，导致本地局域网段拒绝服务。"
            },
            L: {
                l: '本地的 (L)',
                d: "<b>坏：</b>易受攻击的组件未绑定到网络堆栈，攻击者的路径是通过读/写/执行能力。要么：攻击者通过本地（例如，键盘、控制台）或远程（例如，SSH）访问目标系统来利用该漏洞；要么攻击者依赖另一个人的用户交互来执行利用该漏洞所需的操作（例如，使用社会工程学手段诱骗合法用户打开恶意文档）。"
            },
            P: {
                l: '物理的 (P)',
                d: "<b>糟糕：</b>攻击需要攻击者亲自接触或操纵易受攻击的组件。身体接触可能是短暂的（例如，“邪恶女仆”攻击）或持续的。此类攻击的一个例子是冷启动攻击，攻击者在物理接触目标系统后获取磁盘加密密钥。其他例子还包括通过火线 / USB 直接内存访问（DMA）进行的外围设备攻击。"
            }
        },
        AC: {
            L: {
                l: '低 (L)',
                d: "<b>最差：</b>不存在特殊的访问条件或减轻情况。攻击者在攻击易受攻击的组件时可以预期获得可重复的成功。"
            },
            H: {
                l: '高 (H)',
                d: "<b>糟糕：</b>成功的攻击依赖于攻击者无法控制的条件。也就是说，攻击者无法随意成功攻击，而是需要在准备或针对易受攻击组件的执行过程中投入一定可衡量的努力，才能期望成功攻击。"
            }
        },
        PR: {
            N: {
                l: '无 (N)',
                d: "<b>最差：</b>攻击者在攻击之前未经授权，因此无需访问易受攻击系统的任何设置或文件即可进行攻击。"
            },
            L: {
                l: '低 (L)',
                d: "<b>更糟：</b>攻击者需要提供基本用户功能的权限，这些权限通常只能影响用户拥有的设置和文件。或者，具有低权限的攻击者只能访问非敏感资源。"
            },
            H: {
                l: '高 (H)',
                d: "<b>糟糕：</b>攻击者需要提供重大（例如，管理）控制权限的权限，这些权限允许访问易受攻击组件的全局设置和文件。"
            }
        },
        UI: {
            N: {
                l: '无 (N)',
                d: "<b>最差：</b>易受攻击的系统可以在没有任何用户交互的情况下被利用。"
            },
            R: {
                l: '所需的 (R)',
                d: "<b>糟糕：</b>成功利用此漏洞需要用户在漏洞被利用之前采取某些行动。例如，成功的利用可能仅在系统管理员安装应用程序期间才有可能。"
            }
        },

        S: {
            C: {
                l: '改变的 (C)',
                d: "<b>最差：</b>被利用的漏洞可能会影响超出易受攻击组件安全机构管理的安全范围的资源。在这种情况下，易受攻击的组件和受影响的组件是不同的，并且由不同的安全机构管理。"
            },
            U: {
                l: '未改变的 (U)',
                d: "<b>糟糕：</b>被利用的漏洞只能影响由同一安全机构管理的资源。在这种情况下，易受攻击的组件和受影响的组件要么是同一个，要么都是由同一安全机构管理的。"
            }
        },
        C: {
            H: {
                l: '高 (H)',
                d: "<b>最差：</b>机密性完全丧失，导致受影响组件内的所有资源都被泄露给攻击者。或者，仅获得部分受限信息的访问权，但泄露的信息产生了直接且严重的影响。例如，攻击者窃取了管理员的密码，或者窃取了网络服务器的私有加密密钥。"
            },
            L: {
                l: '低 (L)',
                d: "<b>糟糕：</b>机密性部分丧失。获得了部分受限信息的访问权，但攻击者无法控制所获得的信息内容，或者损失的程度或类型是有限的。信息披露不会对受影响组件造成直接且严重的损失。"
            },
            N: {
                l: '无 (N)',
                d: "<b>良好：</b>受影响组件内没有机密性丧失。"
            }
        },
        I: {
            H: {
                l: '高 (H)',
                d: "<b>最差：</b>完整性完全丧失，或者保护完全失效。例如，攻击者能够修改受影响组件保护的任何/所有文件。或者，只有部分文件可以被修改，但恶意修改会对受影响组件产生直接且严重的后果。"
            },
            L: {
                l: '低 (L)',
                d: "<b>糟糕：</b>数据可以被修改，但攻击者无法控制修改的后果，或者修改的量是有限的。数据修改对受影响组件没有直接且严重的冲击。"
            },
            N: {
                l: '无 (N)',
                d: "<b>良好：</b>受影响组件内没有完整性丧失。"
            }
        },
        A: {
            H: {
                l: '高 (H)',
                d: "<b>最差：</b>可用性完全丧失，导致攻击者能够完全阻止对受影响组件中资源的访问；这种丧失是持续的（只要攻击者继续发动攻击）或永久的（即使攻击已经结束，该状况仍然存在）。或者，攻击者有能力拒绝部分可用性，但可用性的丧失对受影响组件产生了直接且严重的后果（例如，攻击者无法破坏现有连接，但可以阻止新连接；攻击者可以反复利用一个漏洞，每次成功的攻击只泄露少量内存，但反复利用后会导致服务完全不可用）。"
            },
            L: {
                l: '低 (L)',
                d: "<b>糟糕：</b>性能降低或资源可用性出现中断。即使可以反复利用该漏洞，攻击者也无法完全阻止合法用户的服务。受影响组件中的资源要么部分时间始终可用，要么全部时间仅部分可用，但总体上对受影响组件没有直接且严重的后果。"
            },
            N: {
                l: '无 (N)',
                d: "<b>良好：</b>受影响组件内的可用性未受影响。"
            }
        }
    };
    
    this.bme = {};
    this.bmgReg = {
        AV: 'NALP',
        AC: 'LH',
        PR: 'NLH',
        UI: 'NR',
        S: 'CU',
        C: 'HLN',
        I: 'HLN',
        A: 'HLN'
    };
    this.bmoReg = {
        AV: 'NALP',
        AC: 'LH',
        C: 'C',
        I: 'C',
        A: 'C'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>严重程度&sdot;分数&sdot;向量</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    
    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CVSS.prototype.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
}, {
    name: "Low",
    bottom: 0.1,
    top: 3.9
}, {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
}, {
    name: "High",
    bottom: 7.0,
    top: 8.9
}, {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
}];

CVSS.prototype.severityRating = function (score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        bottom: 'Not',
        top: 'defined'
    };
};

CVSS.prototype.valueofradio = function(e) {
    for(var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CVSS.prototype.calculate = function () {
    var cvssVersion = "3.1";
    var exploitabilityCoefficient = 8.22;
    var scopeCoefficient = 1.08;

    // Define associative arrays mapping each metric value to the constant used in the CVSS scoring formula.
    var Weight = {
        AV: {
            N: 0.85,
            A: 0.62,
            L: 0.55,
            P: 0.2
        },
        AC: {
            H: 0.44,
            L: 0.77
        },
        PR: {
            U: {
                N: 0.85,
                L: 0.62,
                H: 0.27
            },
            // These values are used if Scope is Unchanged
            C: {
                N: 0.85,
                L: 0.68,
                H: 0.5
            }
        },
        // These values are used if Scope is Changed
        UI: {
            N: 0.85,
            R: 0.62
        },
        S: {
            U: 6.42,
            C: 7.52
        },
        C: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        I: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        A: {
            N: 0,
            L: 0.22,
            H: 0.56
        }
        // C, I and A have the same weights

    };

    var p;
    var val = {}, metricWeight = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] === "undefined" || val[p] === null) {
                return "?";
            }
            metricWeight[p] = Weight[p][val[p]];
        }
    } catch (err) {
        return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
    }
    metricWeight.PR = Weight.PR[val.S][val.PR];
    //
    // CALCULATE THE CVSS BASE SCORE
    //
    var roundUp1 = function Roundup(input) {
        var int_input = Math.round(input * 100000);
        if (int_input % 10000 === 0) {
            return int_input / 100000
        } else {
            return (Math.floor(int_input / 10000) + 1) / 10
        }
    };
    try {
    var baseScore, impactSubScore, impact, exploitability;
    var impactSubScoreMultiplier = (1 - ((1 - metricWeight.C) * (1 - metricWeight.I) * (1 - metricWeight.A)));
    if (val.S === 'U') {
        impactSubScore = metricWeight.S * impactSubScoreMultiplier;
    } else {
        impactSubScore = metricWeight.S * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
    }
    var exploitabalitySubScore = exploitabilityCoefficient * metricWeight.AV * metricWeight.AC * metricWeight.PR * metricWeight.UI;
    if (impactSubScore <= 0) {
        baseScore = 0;
    } else {
        if (val.S === 'U') {
            baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10));
        } else {
            baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * scopeCoefficient, 10));
        }
    }

    return baseScore.toFixed(1);
    } catch (err) {
        return err;
    }
};

CVSS.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
};

CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/PR:.\/UI:.\/S:.\/C:.\/I:.\/A:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

CVSS.prototype.set = function(vec) {
    var newVec = 'CVSS:3.1/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
};

CVSS.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    this.score.innerHTML = s;
    var rating = this.severityRating(s);
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    this.severity.title = rating.bottom + ' - ' + rating.top;
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};