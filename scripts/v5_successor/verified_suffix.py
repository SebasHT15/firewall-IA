"""Experimental greedy suffix verification, never a vocabulary mask.

When an unconstrained greedy prefix uniquely identifies a vocabulary string,
verify every remaining token (including EOS) with a single causal forward pass.
Any mismatch restarts the unchanged native generator. Invalid outputs are never
converted to valid labels. Floating-point kernel differences still require DEV
comparison; this module is not wired into the serving API.
"""
import time


def matching_candidates(candidates, prefix):
    return [candidate for candidate in candidates if candidate[:len(prefix)] == prefix]


def suffix_verified(expected, predicted):
    return bool(expected) and list(expected) == list(predicted)


def compatible_generation(config):
    # These options would change native greedy argmax with a logits processor.
    defaults = dict(repetition_penalty=1.0, encoder_repetition_penalty=1.0,
                    no_repeat_ngram_size=0, encoder_no_repeat_ngram_size=0,
                    min_length=0, min_new_tokens=None, forced_bos_token_id=None,
                    forced_eos_token_id=None, suppress_tokens=None,
                    begin_suppress_tokens=None, bad_words_ids=None,
                    sequence_bias=None, constraints=None, force_words_ids=None,
                    watermarking_config=None, exponential_decay_length_penalty=None,
                    guidance_scale=None, remove_invalid_values=False,
                    renormalize_logits=False, num_beams=1, stop_strings=None,
                    max_time=None, token_healing=False, penalty_alpha=None)
    return all(getattr(config,k,v)==v or (v is False and getattr(config,k,v) is None)
               for k,v in defaults.items())


def generate_verified(m, x, attn, candidates):
    import torch
    mdl, tok, c = m.model, m.tokenizer, m.contract
    info = dict(suffix_verified=False, fallback=False, prefix_tokens=0,
                verification_tokens=0, native_generation=False)

    def fallback():
        info.update(fallback=True,native_generation=True)
        output = mdl.generate(input_ids=x,attention_mask=attn,do_sample=False,
                              max_new_tokens=c.max_new_tokens,
                              eos_token_id=tok.eos_token_id,pad_token_id=tok.eos_token_id)
        return output[0,x.shape[1]:].tolist(), info

    # Transformers 5 stores unset values as None and resolves global defaults
    # at generate() time. Use the very same resolver before inspecting options.
    generation_config,_ = mdl._prepare_generation_config(
        None,do_sample=False,max_new_tokens=c.max_new_tokens,
        eos_token_id=tok.eos_token_id,pad_token_id=tok.eos_token_id)
    if not compatible_generation(generation_config):
        info['fallback_reason']='unsupported_generation_settings'
        return fallback()
    result = mdl(input_ids=x,attention_mask=attn,use_cache=True,logits_to_keep=1)
    cache = result.past_key_values
    prefix = [int(result.logits[0,-1].argmax().item())]
    while len(prefix) <= c.max_new_tokens:
        info['prefix_tokens'] = len(prefix)
        matches = matching_candidates(candidates,prefix)
        if len(matches) == 1 and len(matches[0]) <= c.max_new_tokens:
            candidate = matches[0]
            suffix = candidate[len(prefix):]
            if not suffix:
                if prefix[-1] != tok.eos_token_id:
                    return fallback()
                info['suffix_verified'] = True
                return prefix, info
            # The final predicted prefix token is not in KV yet. Feed it and
            # all candidate tokens before EOS, then verify the next-token argmax
            # at EVERY position. No candidate token is accepted without a check.
            proposed = [prefix[-1]] + suffix[:-1]
            verified = mdl(input_ids=torch.tensor([proposed],device=x.device),
                           attention_mask=torch.ones((1,x.shape[1]+len(prefix)-1+len(proposed)),
                                                     device=x.device,dtype=attn.dtype),
                           past_key_values=cache,use_cache=True,logits_to_keep=0)
            predicted = verified.logits[0].argmax(-1).tolist()
            info['verification_tokens'] = len(suffix)
            if suffix_verified(suffix,predicted) and candidate[-1] == tok.eos_token_id:
                info['suffix_verified'] = True
                return candidate, info
            return fallback()
        if not matches or prefix[-1] == tok.eos_token_id or len(prefix) == c.max_new_tokens:
            return fallback()
        result = mdl(input_ids=torch.tensor([[prefix[-1]]],device=x.device),
                     attention_mask=torch.ones((1,x.shape[1]+len(prefix)),device=x.device,dtype=attn.dtype),
                     past_key_values=cache,use_cache=True,logits_to_keep=1)
        cache = result.past_key_values
        prefix.append(int(result.logits[0,-1].argmax().item()))
    return fallback()


def candidates_for(m):
    # Native training encoding, including EOS. Never guess token boundaries by
    # separately encoding a label string or using a special-token literal.
    import v5_tokenization as T
    base = T.encode_prompt(m.tokenizer,m.contract.template,'')
    candidates=[]
    for label in m.contract.vocabulary:
        full=T.encode_prompt(m.tokenizer,m.contract.template,'',output=label)
        if full[:len(base)] != base:
            raise ValueError('Output tokenization changes prompt prefix')
        candidate=full[len(base):]
        if not candidate or candidate[-1]!=m.tokenizer.eos_token_id:
            raise ValueError('Candidate lacks native EOS')
        candidates.append(candidate)
    return candidates


def classify_verified(m, text, candidates):
    import torch
    import v5_inference_core as core
    t0=time.perf_counter()
    try:
        ids=core.encode_canonical(m.contract,m.tokenizer,text)
    except core.V5ContentRejected as exc:
        elapsed=(time.perf_counter()-t0)*1000
        parsed=core.OC.ParsedOutput(core.OC.INVALID,None,None,'content_rejected')
        return parsed,dict(encode_ms=elapsed,tokenize_ms=0.,transfer_ms=0.,generate_ms=0.,
                           decode_ms=0.,parse_ms=0.,generated_tokens=0,prompt_tokens=0,
                           ended_with_eos=False,content_rejected=str(exc),
                           pipeline_ms=elapsed,suffix_verified=False,fallback=False)
    t1=time.perf_counter()
    x=torch.tensor([ids],device=m.device)
    attn=torch.ones_like(x)
    core.device_sync(m.device)
    t2=time.perf_counter()
    with torch.inference_mode():
        new,info=generate_verified(m,x,attn,candidates)
    core.device_sync(m.device)
    t3=time.perf_counter()
    raw=m.tokenizer.decode(new,skip_special_tokens=True)
    ended=bool(new and m.tokenizer.eos_token_id in new)
    t4=time.perf_counter()
    parsed=core.OC.parse_v5_output(raw,m.contract.vocabulary,ended_with_eos=ended)
    t5=time.perf_counter()
    return parsed,dict(info,pipeline_ms=(t5-t0)*1000,
                       encode_ms=(t1-t0)*1000,tokenize_ms=0.,transfer_ms=(t2-t1)*1000,
                       generate_ms=(t3-t2)*1000,decode_ms=(t4-t3)*1000,parse_ms=(t5-t4)*1000,
                       generated_tokens=len(new),prompt_tokens=len(ids),raw_text=raw,
                       ended_with_eos=ended)
