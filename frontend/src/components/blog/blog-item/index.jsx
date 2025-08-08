import PropTypes from "prop-types";
import { Link } from "react-router-dom";
import SwiperCore, { Autoplay } from "swiper";
import { Swiper, SwiperSlide } from "swiper/react";
import { slugify } from "../../../utils";

SwiperCore.use([Autoplay]);

const BlogItem = ({ data }) => {
    const cate = data.categories.map((value, i) => {
        return (
            <Link
                className="category"
                to={process.env.PUBLIC_URL + `/category/${slugify(value)}`}
                key={i}
            >
                {value}
                {i !== data.categories.length - 1 && ","}
            </Link>
        );
    });

    return (
        <div className="post-item">
            {data?.format === "slider" && (
                <div className="thumb">
                    <Swiper
                        className="post-gallery"
                        spaceBetween={0}
                        slidesPerView={1}
                        loop
                        autoplay
                    >
                        {data.sliderThumb &&
                            data.sliderThumb.map((single, key) => {
                                return (
                                    <SwiperSlide key={key}>
                                        <Link
                                            to={
                                                process.env.PUBLIC_URL +
                                                `/blog-details/${data.id}`
                                            }
                                        >
                                            <img
                                                key={key}
                                                src={`${process.env.PUBLIC_URL}/${single.thumb}`}
                                                alt="Alexis"
                                            />
                                        </Link>
                                    </SwiperSlide>
                                );
                            })}
                    </Swiper>
                </div>
            )}
            {data?.format === "thumbnail" && (
                <div className="thumb">
                    <Link
                        to={process.env.PUBLIC_URL + `/blog-details/${data.id}`}
                    >
                        <img
                            src={`${process.env.PUBLIC_URL}/${data.media.thumb}`}
                            alt="Alexis-Blog"
                        />
                    </Link>
                </div>
            )}
            {data?.format === "audio" && (
                <div className="post-audio">
                    <div className="embed-responsive">
                        <iframe title="title" src={data.audioSrc}></iframe>
                    </div>
                </div>
            )}
            {data?.format === "quote" && (
                <div className="thumb">
                    <img
                        src={`${process.env.PUBLIC_URL}/${data.media.thumb}`}
                        alt="Alexis-Blog"
                    />
                    <div className="overlay-content">
                        <div className="quotes">
                            <div className="icon">
                                <i className="icon_quotations"></i>
                            </div>
                            <p>{data.quoteContent}</p>
                            <div className="name">- Chirs Ivan -</div>
                        </div>
                    </div>
                </div>
            )}
            <div className="content">
                <div className="meta">
                    <Link
                        className="post-date"
                        to={
                            process.env.PUBLIC_URL +
                            `/date/${slugify(data.date)}`
                        }
                    >
                        {data.date}
                    </Link>{" "}
                    <span>/</span>{" "}
                    <Link
                        className="author"
                        to={
                            process.env.PUBLIC_URL +
                            `/author/${slugify(data.author)}`
                        }
                    >
                        {data.author}
                    </Link>{" "}
                    <span>/</span> <span className="cate-link">{cate}</span>
                </div>
                <h4 className="title">
                    <Link
                        to={process.env.PUBLIC_URL + `/blog-details/${data.id}`}
                    >
                        {data.title}
                    </Link>
                </h4>
                <Link
                    className="btn-link"
                    to={process.env.PUBLIC_URL + `/blog-details/${data.id}`}
                >
                    Continue
                </Link>
            </div>
        </div>
    );
};

BlogItem.propTypes = {
    data: PropTypes.object,
};

export default BlogItem;
