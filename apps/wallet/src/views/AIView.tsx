import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import ReactMarkdown from 'react-markdown';
import { useAppStore } from '../store/appStore';
import { ArrowLeft, Send, Sparkles, Bot, User, Loader2, Info } from 'lucide-react';
import { cn } from '../utils/cn';
import { chatWithAi } from '../lib/api';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  sources?: { uri: string; title: string }[];
}

export function AIView() {
  const setView = useAppStore((state) => state.setView);
  const isSubscribed = useAppStore((state) => state.isSubscribed);
  const firstMessageTimestamp = useAppStore((state) => state.firstMessageTimestamp);
  const setFirstMessageTimestamp = useAppStore((state) => state.setFirstMessageTimestamp);

  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: "Oxidity AI is online. Straight shooting market analysis ready. What token are we looking at?",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    // Subscription Check
    if (!isSubscribed) {
      if (firstMessageTimestamp) {
        const now = Date.now();
        const twentyFourHours = 24 * 60 * 60 * 1000;
        if (now - firstMessageTimestamp < twentyFourHours) {
          setView('subscription');
          return;
        } else {
          // 24 hours have passed, this is a new "free" message
          setFirstMessageTimestamp(now);
        }
      } else {
        // First message ever
        setFirstMessageTimestamp(Date.now());
      }
    }

    const userMessage: Message = {
      role: 'user',
      content: input,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await chatWithAi(userMessage.content);
      const assistantMessage: Message = {
        role: 'assistant',
        content: response.content || "I'm sorry, I couldn't process that request.",
        timestamp: new Date(),
        sources: response.sources,
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (error) {
      console.error('AI Error:', error);
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: "I'm having trouble connecting to my brain right now. Please try again in a moment.",
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const suggestions = [
    "What's the trend for ETH today?",
    "Top bullish tokens right now",
    "Is it a good time to buy BTC?",
    "Explain Oxidity's gas saving",
  ];

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="absolute inset-0 bg-zinc-950 flex flex-col z-[60]"
    >
      {/* Header */}
      <div className="p-6 border-b border-white/5 flex items-center gap-4 bg-zinc-950/80 backdrop-blur-xl sticky top-0 z-10">
        <button
          onClick={() => setView('main')}
          className="p-2 hover:bg-zinc-900 rounded-full transition-colors"
        >
          <ArrowLeft className="w-6 h-6" />
        </button>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-500 flex items-center justify-center shadow-[0_0_20px_rgba(99,102,241,0.3)]">
            <Sparkles className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold tracking-tight">Oxidity Wallet AI</h2>
              {isSubscribed && (
                <span className="bg-indigo-500 text-[8px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded-md text-white">
                  Pro
                </span>
              )}
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest">Market Analyzer</span>
            </div>
          </div>
        </div>
        {!isSubscribed && (
          <button
            onClick={() => setView('subscription')}
            className="ml-auto bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 text-[10px] font-bold uppercase tracking-widest px-3 py-1.5 rounded-full border border-indigo-500/20 transition-colors"
          >
            Upgrade
          </button>
        )}
      </div>

      {/* Chat Area */}
      <div 
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-6 space-y-6 scroll-smooth"
      >
        {messages.map((msg, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className={cn(
              "flex flex-col gap-2",
              msg.role === 'user' ? "items-end" : "items-start"
            )}
          >
            <div className={cn(
              "flex gap-3 max-w-[85%]",
              msg.role === 'user' ? "flex-row-reverse" : ""
            )}>
              <div className={cn(
                "w-8 h-8 rounded-lg flex items-center justify-center shrink-0",
                msg.role === 'user' ? "bg-zinc-800" : "bg-indigo-500/20"
              )}>
                {msg.role === 'user' ? <User className="w-4 h-4 text-zinc-400" /> : <Bot className="w-4 h-4 text-indigo-400" />}
              </div>
              <div className={cn(
                "p-4 rounded-2xl text-sm leading-relaxed",
                msg.role === 'user' 
                  ? "bg-indigo-600 text-white rounded-tr-none" 
                  : "bg-zinc-900 text-zinc-300 rounded-tl-none border border-white/5"
              )}>
                <div className="markdown-body">
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              </div>
            </div>
            {msg.sources && msg.sources.length > 0 && (
              <div className="ml-11 flex flex-wrap gap-2 mt-1">
                {msg.sources.map((source, idx) => (
                  <a
                    key={idx}
                    href={source.uri}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] bg-zinc-900 border border-white/5 px-2 py-1 rounded-md text-indigo-400 hover:text-indigo-300 transition-colors flex items-center gap-1"
                  >
                    <Info className="w-2.5 h-2.5" />
                    {source.title.length > 20 ? source.title.substring(0, 20) + '...' : source.title}
                  </a>
                ))}
              </div>
            )}
          </motion.div>
        ))}
        {isLoading && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex gap-3"
          >
            <div className="w-8 h-8 rounded-lg bg-indigo-500/20 flex items-center justify-center">
              <Bot className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="bg-zinc-900 border border-white/5 p-4 rounded-2xl rounded-tl-none flex items-center gap-2">
              <Loader2 className="w-4 h-4 text-indigo-400 animate-spin" />
              <span className="text-xs text-zinc-500">Scouring the web for alpha...</span>
            </div>
          </motion.div>
        )}
      </div>

      {/* Input Area */}
      <div className="p-6 bg-zinc-950 border-t border-white/5">
        {messages.length === 1 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {suggestions.map((s, i) => (
              <button
                key={i}
                onClick={() => setInput(s)}
                className="text-xs bg-zinc-900 hover:bg-zinc-800 border border-white/5 px-3 py-2 rounded-full text-zinc-400 transition-colors"
              >
                {s}
              </button>
            ))}
          </div>
        )}
        <div className="relative">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Ask about market trends..."
            className="w-full bg-zinc-900 border border-white/10 rounded-2xl py-4 pl-4 pr-14 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors"
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            className="absolute right-2 top-2 bottom-2 w-10 bg-indigo-500 rounded-xl flex items-center justify-center text-white disabled:opacity-50 disabled:cursor-not-allowed hover:bg-indigo-600 transition-colors"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>
        <p className="text-[10px] text-zinc-600 text-center mt-4 flex items-center justify-center gap-1">
          <Info className="w-3 h-3" />
          AI can make mistakes. Not financial advice.
        </p>
      </div>
    </motion.div>
  );
}
