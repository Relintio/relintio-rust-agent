use serde_json::Value;

pub struct ObsidianInjector {
    script_id: &'static str,
    max_body_bytes: usize,
}

impl Default for ObsidianInjector {
    fn default() -> Self {
        Self {
            script_id: "relintio-obsidian",
            max_body_bytes: 2 * 1024 * 1024,
        }
    }
}

impl ObsidianInjector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build client-side protection script based on config rules.
    pub fn build_client_script(&self, rules: &Value) -> String {
        let mut js = String::new();

        if rules.get("guard_rightclick").and_then(|v| v.as_bool()).unwrap_or(false) {
            js.push_str("document.addEventListener('contextmenu',e=>e.preventDefault());");
        }

        if rules.get("guard_devtools").and_then(|v| v.as_bool()).unwrap_or(false) {
            js.push_str("document.onkeydown=function(e){if(e.keyCode==123||(e.ctrlKey&&e.shiftKey&&e.keyCode=='I'.charCodeAt(0))||(e.ctrlKey&&e.shiftKey&&e.keyCode=='J'.charCodeAt(0))||(e.ctrlKey&&e.keyCode=='U'.charCodeAt(0)))return false;};");
        }

        if rules.get("guard_copy").and_then(|v| v.as_bool()).unwrap_or(false) {
            js.push_str("document.addEventListener('copy',function(e){try{var t=(e.clipboardData||window.clipboardData);if(!t)return;var s=window.getSelection?String(window.getSelection()):'';if(!s)return;t.setData('text/plain',s+'\\n\\n[Protected by Relintio]');e.preventDefault();}catch(_e){}});");
        }

        let mode = rules.get("obsidian_mode").and_then(|v| v.as_str()).unwrap_or("compat");

        if rules.get("obsidian_text").and_then(|v| v.as_bool()).unwrap_or(false) && mode == "aggressive" {
            js.push_str("(function(){function s(n){if(n.nodeType===3){n.nodeValue=n.nodeValue.split('').join('\\u200C');}else if(n.nodeType===1&&n.tagName!=='SCRIPT'&&n.tagName!=='STYLE'){for(var i=0;i<n.childNodes.length;i++){s(n.childNodes[i]);}}}}window.addEventListener('load',function(){try{s(document.body);}catch(_e){}},{once:true});})();");
        }

        if rules.get("obsidian_css").and_then(|v| v.as_bool()).unwrap_or(false) {
            if mode == "aggressive" {
                js.push_str("(function(){function run(){try{var n=['ax-99','bz-22','c-al'];var all=document.querySelectorAll('*');for(var j=0;j<all.length;j++){all[j].classList.add(n[Math.floor(Math.random()*n.length)]);}}catch(_e){}}window.addEventListener('load',function(){setTimeout(run,50);},{once:true});})();");
            } else {
                js.push_str("(function(){function run(){try{var roots=['#app','#__next','[data-reactroot]'];for(var i=0;i<roots.length;i++){if(document.querySelector(roots[i]))return;}var n=['ax-99','bz-22','c-al'];var all=document.querySelectorAll('*');for(var j=0;j<all.length;j++){all[j].classList.add(n[Math.floor(Math.random()*n.length)]);}}catch(_e){}}if('requestIdleCallback' in window){requestIdleCallback(run,{timeout:1200});}else{window.addEventListener('load',function(){setTimeout(run,250);});}})();");
            }
        }

        js
    }

    /// Inject script tag inside </body> of HTML response body.
    pub fn inject_into_html(&self, body: &[u8], rules: &Value) -> Vec<u8> {
        if body.is_empty() || body.len() > self.max_body_bytes {
            return body.to_vec();
        }

        // Simplistic check to see if it's text/html.
        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return body.to_vec(),
        };

        if !body_str.to_lowercase().contains("<html") {
            return body.to_vec();
        }

        let script = self.build_client_script(rules);
        if script.is_empty() {
            return body.to_vec();
        }

        let injection = format!("<script id=\"{}\">{}</script>", self.script_id, script);

        if let Some(pos) = body_str.to_lowercase().rfind("</body>") {
            let mut new_body = Vec::with_capacity(body.len() + injection.len());
            new_body.extend_from_slice(&body[..pos]);
            new_body.extend_from_slice(injection.as_bytes());
            new_body.extend_from_slice(&body[pos..]);
            new_body
        } else {
            let mut new_body = body.to_vec();
            new_body.extend_from_slice(injection.as_bytes());
            new_body
        }
    }
}
